-- +goose Up
-- The run events stream had a hub, an endpoint and a subscriber, and no
-- publisher — because the hub lives in the api process while tasks are
-- ingested by the gateway and runs advanced by the scheduler. The one bus all
-- three share is this database, so the database publishes: a status change on a
-- task, a run or a fleet raises a notification the api listens for and fans out
-- to browsers. A trigger cannot be forgotten at a call site.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notify_run_event() RETURNS trigger AS $$
DECLARE
  rid uuid;
  payload text;
BEGIN
  IF TG_TABLE_NAME = 'scan_run' THEN
    rid := NEW.id;
    payload := json_build_object('kind','run','run_id',rid,'status',NEW.status)::text;
  ELSIF TG_TABLE_NAME = 'scan_task' THEN
    rid := NEW.run_id;
    payload := json_build_object('kind','task','run_id',rid,'stage',NEW.stage,'status',NEW.status)::text;
  ELSE
    rid := NEW.run_id;
    payload := json_build_object('kind','fleet','run_id',rid,'status',NEW.status)::text;
  END IF;
  PERFORM pg_notify('run_events', payload);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS scan_task_notify ON scan_task;
CREATE TRIGGER scan_task_notify AFTER INSERT OR UPDATE OF status ON scan_task
  FOR EACH ROW EXECUTE FUNCTION notify_run_event();
DROP TRIGGER IF EXISTS scan_run_notify ON scan_run;
CREATE TRIGGER scan_run_notify AFTER UPDATE OF status ON scan_run
  FOR EACH ROW EXECUTE FUNCTION notify_run_event();
DROP TRIGGER IF EXISTS run_fleet_notify ON run_fleet;
CREATE TRIGGER run_fleet_notify AFTER INSERT OR UPDATE OF status, error ON run_fleet
  FOR EACH ROW EXECUTE FUNCTION notify_run_event();

-- +goose Down
DROP TRIGGER IF EXISTS run_fleet_notify ON run_fleet;
DROP TRIGGER IF EXISTS scan_run_notify ON scan_run;
DROP TRIGGER IF EXISTS scan_task_notify ON scan_task;
DROP FUNCTION IF EXISTS notify_run_event();
