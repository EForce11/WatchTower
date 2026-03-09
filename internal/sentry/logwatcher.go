package sentry

import (
	"bufio"
	"context"
	"log"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// LogWatcher monitors log files for new entries using inotify (fsnotify).
type LogWatcher struct {
	watcher  *fsnotify.Watcher
	logPaths []string
	events   chan LogEvent

	// offsets tracks the last read position per file path.
	mu      sync.Mutex
	offsets map[string]int64
}

// LogEvent represents a new log line detected in a watched file.
type LogEvent struct {
	FilePath  string
	Line      string
	Timestamp int64
}

// NewLogWatcher creates a new LogWatcher that monitors the given file paths.
// Returns an error if any path cannot be added to the underlying watcher.
func NewLogWatcher(logPaths []string) (*LogWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	offsets := make(map[string]int64, len(logPaths))

	for _, path := range logPaths {
		if err := watcher.Add(path); err != nil {
			_ = watcher.Close()
			return nil, err
		}

		// Initialise offset to the current end of file so only *new* lines
		// written after Watch() is called are emitted.
		info, err := os.Stat(path)
		if err == nil {
			offsets[path] = info.Size()
		} else {
			offsets[path] = 0
		}
	}

	return &LogWatcher{
		watcher:  watcher,
		logPaths: logPaths,
		events:   make(chan LogEvent, 100),
		offsets:  offsets,
	}, nil
}

// Watch starts a background goroutine that monitors all registered log files.
// It returns when ctx is cancelled.
func (lw *LogWatcher) Watch(ctx context.Context) {
	go func() {
		for {
			select {
			case event, ok := <-lw.watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) {
					lw.handleFileChange(event.Name)
				}
			case err, ok := <-lw.watcher.Errors:
				if !ok {
					return
				}
				log.Printf("[logwatcher] watcher error: %v", err)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// handleFileChange reads any lines appended to filePath since the last read.
func (lw *LogWatcher) handleFileChange(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("[logwatcher] error opening %s: %v", filePath, err)
		return
	}
	defer file.Close()

	lw.mu.Lock()
	offset := lw.offsets[filePath]
	lw.mu.Unlock()

	// Seek to where we last finished reading.
	if _, err := file.Seek(offset, os.SEEK_SET); err != nil {
		log.Printf("[logwatcher] seek error on %s: %v", filePath, err)
		return
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		lw.events <- LogEvent{
			FilePath:  filePath,
			Line:      line,
			Timestamp: time.Now().Unix(),
		}
	}

	// Update the stored offset.
	newOffset, err := file.Seek(0, os.SEEK_CUR)
	if err == nil {
		lw.mu.Lock()
		lw.offsets[filePath] = newOffset
		lw.mu.Unlock()
	}
}

// Events returns the read-only channel on which LogEvents are delivered.
func (lw *LogWatcher) Events() <-chan LogEvent {
	return lw.events
}

// Close stops the underlying fsnotify watcher and closes the events channel.
// Callers must not send on or receive from Events() after Close returns.
func (lw *LogWatcher) Close() error {
	close(lw.events)
	return lw.watcher.Close()
}
