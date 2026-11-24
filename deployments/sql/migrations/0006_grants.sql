-- Privileges: everything is owned by wt_owner, so these grants actually bind.
GRANT SELECT, INSERT, UPDATE ON agents, enrollment_tokens, certificates, incidents,
      response_actions, pending_approvals, baselines, ip_reputation, ioc_indicators,
      correlation_state TO wt_core;
GRANT SELECT, INSERT ON events, detections TO wt_core;
GRANT SELECT ON admin_keys TO wt_core;                -- admin keys are added via wt_owner only
GRANT SELECT, INSERT ON audit_logs TO wt_core;        -- no UPDATE/DELETE/TRUNCATE
GRANT USAGE ON SEQUENCE audit_logs_id_seq, ioc_indicators_id_seq TO wt_core;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO wt_grafana;
