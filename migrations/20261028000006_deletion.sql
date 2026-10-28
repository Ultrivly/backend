










ALTER TABLE organizations
    ADD COLUMN deleted_at  timestamptz,
    ADD COLUMN purge_after timestamptz,
    ADD CONSTRAINT organizations_deletion_check CHECK ((deleted_at IS NULL) = (purge_after IS NULL));

ALTER TABLE workspaces
    ADD COLUMN deleted_at  timestamptz,
    ADD COLUMN purge_after timestamptz,
    ADD CONSTRAINT workspaces_deletion_check CHECK ((deleted_at IS NULL) = (purge_after IS NULL));

ALTER TABLE cases
    ADD COLUMN deleted_at  timestamptz,
    ADD COLUMN purge_after timestamptz,
    ADD CONSTRAINT cases_deletion_check CHECK ((deleted_at IS NULL) = (purge_after IS NULL));

ALTER TABLE attachments
    ADD COLUMN deleted_at  timestamptz,
    ADD COLUMN purge_after timestamptz,
    ADD CONSTRAINT attachments_deletion_check CHECK ((deleted_at IS NULL) = (purge_after IS NULL));

CREATE INDEX organizations_purge_idx ON organizations (purge_after) WHERE purge_after IS NOT NULL;
CREATE INDEX workspaces_purge_idx ON workspaces (purge_after) WHERE purge_after IS NOT NULL;
CREATE INDEX cases_purge_idx ON cases (purge_after) WHERE purge_after IS NOT NULL;
CREATE INDEX attachments_purge_idx ON attachments (purge_after) WHERE purge_after IS NOT NULL;



ALTER TABLE workspaces DROP CONSTRAINT workspaces_org_id_fkey,
    ADD CONSTRAINT workspaces_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE memberships DROP CONSTRAINT memberships_org_id_fkey,
    ADD CONSTRAINT memberships_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE roles DROP CONSTRAINT roles_org_id_fkey,
    ADD CONSTRAINT roles_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE departments DROP CONSTRAINT departments_org_id_fkey,
    ADD CONSTRAINT departments_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE teams DROP CONSTRAINT teams_org_id_fkey,
    ADD CONSTRAINT teams_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE queues DROP CONSTRAINT queues_org_id_fkey,
    ADD CONSTRAINT queues_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE contacts DROP CONSTRAINT contacts_org_id_fkey,
    ADD CONSTRAINT contacts_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE case_statuses DROP CONSTRAINT case_statuses_org_id_fkey,
    ADD CONSTRAINT case_statuses_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE case_priorities DROP CONSTRAINT case_priorities_org_id_fkey,
    ADD CONSTRAINT case_priorities_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE case_number_counters DROP CONSTRAINT case_number_counters_org_id_fkey,
    ADD CONSTRAINT case_number_counters_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE cases DROP CONSTRAINT cases_org_id_fkey,
    ADD CONSTRAINT cases_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE jobs DROP CONSTRAINT jobs_org_id_fkey,
    ADD CONSTRAINT jobs_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE domain_events DROP CONSTRAINT domain_events_org_id_fkey,
    ADD CONSTRAINT domain_events_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;


ALTER TABLE audit_events DROP CONSTRAINT audit_events_org_id_fkey,
    ADD CONSTRAINT audit_events_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE idempotency_keys DROP CONSTRAINT idempotency_keys_org_id_fkey,
    ADD CONSTRAINT idempotency_keys_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;



ALTER TABLE teams DROP CONSTRAINT teams_org_id_workspace_id_fkey,
    ADD CONSTRAINT teams_org_id_workspace_id_fkey FOREIGN KEY (org_id, workspace_id)
        REFERENCES workspaces (org_id, id) ON DELETE CASCADE;
ALTER TABLE queues DROP CONSTRAINT queues_org_id_workspace_id_fkey,
    ADD CONSTRAINT queues_org_id_workspace_id_fkey FOREIGN KEY (org_id, workspace_id)
        REFERENCES workspaces (org_id, id) ON DELETE CASCADE;
ALTER TABLE cases DROP CONSTRAINT cases_org_id_workspace_id_fkey,
    ADD CONSTRAINT cases_org_id_workspace_id_fkey FOREIGN KEY (org_id, workspace_id)
        REFERENCES workspaces (org_id, id) ON DELETE CASCADE;



ALTER TABLE case_messages DROP CONSTRAINT case_messages_org_id_case_id_fkey,
    ADD CONSTRAINT case_messages_org_id_case_id_fkey FOREIGN KEY (org_id, case_id)
        REFERENCES cases (org_id, id) ON DELETE CASCADE;
ALTER TABLE case_events DROP CONSTRAINT case_events_org_id_case_id_fkey,
    ADD CONSTRAINT case_events_org_id_case_id_fkey FOREIGN KEY (org_id, case_id)
        REFERENCES cases (org_id, id) ON DELETE CASCADE;
ALTER TABLE attachments DROP CONSTRAINT attachments_org_id_case_id_fkey,
    ADD CONSTRAINT attachments_org_id_case_id_fkey FOREIGN KEY (org_id, case_id)
        REFERENCES cases (org_id, id) ON DELETE CASCADE;
ALTER TABLE attachments DROP CONSTRAINT attachments_org_id_message_id_fkey,
    ADD CONSTRAINT attachments_org_id_message_id_fkey FOREIGN KEY (org_id, message_id)
        REFERENCES case_messages (org_id, id) ON DELETE CASCADE;





ALTER TABLE teams DROP CONSTRAINT teams_org_id_department_id_fkey,
    ADD CONSTRAINT teams_org_id_department_id_fkey FOREIGN KEY (org_id, department_id)
        REFERENCES departments (org_id, id) ON DELETE SET NULL (department_id);
ALTER TABLE queues DROP CONSTRAINT queues_org_id_team_id_fkey,
    ADD CONSTRAINT queues_org_id_team_id_fkey FOREIGN KEY (org_id, team_id)
        REFERENCES teams (org_id, id) ON DELETE SET NULL (team_id);
ALTER TABLE cases DROP CONSTRAINT cases_org_id_team_id_fkey,
    ADD CONSTRAINT cases_org_id_team_id_fkey FOREIGN KEY (org_id, team_id)
        REFERENCES teams (org_id, id) ON DELETE SET NULL (team_id);
ALTER TABLE cases DROP CONSTRAINT cases_org_id_assignee_user_id_fkey,
    ADD CONSTRAINT cases_org_id_assignee_user_id_fkey FOREIGN KEY (org_id, assignee_user_id)
        REFERENCES memberships (org_id, user_id) ON DELETE SET NULL (assignee_user_id);







ALTER TABLE cases DROP CONSTRAINT cases_org_id_status_id_fkey,
    ADD CONSTRAINT cases_org_id_status_id_fkey FOREIGN KEY (org_id, status_id)
        REFERENCES case_statuses (org_id, id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE cases DROP CONSTRAINT cases_org_id_priority_id_fkey,
    ADD CONSTRAINT cases_org_id_priority_id_fkey FOREIGN KEY (org_id, priority_id)
        REFERENCES case_priorities (org_id, id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE cases DROP CONSTRAINT cases_org_id_requester_contact_id_fkey,
    ADD CONSTRAINT cases_org_id_requester_contact_id_fkey FOREIGN KEY (org_id, requester_contact_id)
        REFERENCES contacts (org_id, id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE case_messages DROP CONSTRAINT case_messages_org_id_author_contact_id_fkey,
    ADD CONSTRAINT case_messages_org_id_author_contact_id_fkey FOREIGN KEY (org_id, author_contact_id)
        REFERENCES contacts (org_id, id) DEFERRABLE INITIALLY IMMEDIATE;






CREATE TABLE blob_deletions (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    
    storage_key     text NOT NULL,
    is_prefix       boolean NOT NULL DEFAULT false,
    attempts        integer NOT NULL DEFAULT 0,
    last_error      text,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (NOT is_prefix OR storage_key LIKE '%/')
);

CREATE INDEX blob_deletions_due_idx ON blob_deletions (next_attempt_at);

CREATE FUNCTION queue_attachment_blob_deletion() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO blob_deletions (storage_key) VALUES (OLD.storage_key);
    RETURN OLD;
END;
$$;

CREATE TRIGGER attachments_queue_blob_deletion AFTER DELETE ON attachments
    FOR EACH ROW EXECUTE FUNCTION queue_attachment_blob_deletion();
