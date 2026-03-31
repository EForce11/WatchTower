package sentry

import (
	"context"
	"log"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// SystemMetrics holds a snapshot of system resource usage at a point in time.
type SystemMetrics struct {
	// Timestamp is the Unix epoch (seconds) when the snapshot was taken.
	Timestamp int64

	// CPUPercent is the overall CPU utilisation in the range [0, 100].
	CPUPercent float64

	// MemoryPercent is the virtual-memory utilisation in the range [0, 100].
	MemoryPercent float64

	// MemoryUsedMB is the number of megabytes currently in use.
	MemoryUsedMB uint64

	// DiskPercent is the root filesystem utilisation in the range [0, 100].
	DiskPercent float64

	// DiskUsedGB is the number of gigabytes used on the root filesystem.
	DiskUsedGB uint64

	// NetworkBytesSent is the cumulative bytes transmitted since boot.
	NetworkBytesSent uint64

	// NetworkBytesRecv is the cumulative bytes received since boot.
	NetworkBytesRecv uint64
}

// MetricsCollector periodically samples system resources and publishes the
// results on a buffered channel.
type MetricsCollector struct {
	interval time.Duration
	metrics  chan SystemMetrics
}

// NewMetricsCollector creates a MetricsCollector that collects metrics at the
// given interval.  The internal channel is buffered with a capacity of 10 so
// that slow consumers do not block the collection goroutine.
func NewMetricsCollector(interval time.Duration) *MetricsCollector {
	return &MetricsCollector{
		interval: interval,
		metrics:  make(chan SystemMetrics, 10),
	}
}

// Start launches a background goroutine that performs an immediate collection
// and then repeats every mc.interval until ctx is cancelled.
func (mc *MetricsCollector) Start(ctx context.Context) {
	go func() {
		// Collect immediately so the first metric is available without delay.
		mc.collect()

		ticker := time.NewTicker(mc.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				mc.collect()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Metrics returns the read-only channel on which SystemMetrics snapshots are
// delivered.
func (mc *MetricsCollector) Metrics() <-chan SystemMetrics {
	return mc.metrics
}

// Close closes the metrics channel.  Callers must not receive from Metrics()
// after Close returns.
func (mc *MetricsCollector) Close() {
	close(mc.metrics)
}

// collect gathers a single system snapshot and non-blockingly sends it on the
// channel.  If the channel is full the snapshot is logged and discarded rather
// than blocking the goroutine.
func (mc *MetricsCollector) collect() {
	snapshot := SystemMetrics{
		Timestamp: time.Now().Unix(),
	}

	// ── CPU ──────────────────────────────────────────────────────────────────
	// false = non-per-CPU, 0 interval = compare against last sample taken by
	// the OS (returns immediately on Linux).
	cpuPcts, err := cpu.Percent(0, false)
	if err != nil {
		log.Printf("[metrics] cpu.Percent error: %v", err)
	} else if len(cpuPcts) > 0 {
		snapshot.CPUPercent = cpuPcts[0]
	}

	// ── Memory ───────────────────────────────────────────────────────────────
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		log.Printf("[metrics] mem.VirtualMemory error: %v", err)
	} else {
		snapshot.MemoryPercent = vmStat.UsedPercent
		snapshot.MemoryUsedMB = vmStat.Used / (1024 * 1024)
	}

	// ── Disk ─────────────────────────────────────────────────────────────────
	diskStat, err := disk.Usage("/")
	if err != nil {
		log.Printf("[metrics] disk.Usage error: %v", err)
	} else {
		snapshot.DiskPercent = diskStat.UsedPercent
		snapshot.DiskUsedGB = diskStat.Used / (1024 * 1024 * 1024)
	}

	// ── Network ──────────────────────────────────────────────────────────────
	// false = aggregate across all interfaces (single IOCountersStat returned).
	netStats, err := net.IOCounters(false)
	if err != nil {
		log.Printf("[metrics] net.IOCounters error: %v", err)
	} else if len(netStats) > 0 {
		snapshot.NetworkBytesSent = netStats[0].BytesSent
		snapshot.NetworkBytesRecv = netStats[0].BytesRecv
	}

	// Non-blocking send: drop the snapshot if the consumer hasn't drained the
	// channel yet rather than stalling the collection loop.
	select {
	case mc.metrics <- snapshot:
	default:
		log.Printf("[metrics] channel full – dropping snapshot at ts=%d", snapshot.Timestamp)
	}
}
