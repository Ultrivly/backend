

CREATE TABLE departments (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations (id),
    name        text NOT NULL CHECK (length(trim(name)) > 0),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    UNIQUE (org_id, name)
);

CREATE TRIGGER departments_updated_at BEFORE UPDATE ON departments
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE teams (
    id            uuid PRIMARY KEY,
    org_id        uuid NOT NULL REFERENCES organizations (id),
    workspace_id  uuid NOT NULL,
    department_id uuid,
    name          text NOT NULL CHECK (length(trim(name)) > 0),
    archived_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    UNIQUE (workspace_id, name),
    FOREIGN KEY (org_id, workspace_id) REFERENCES workspaces (org_id, id),
    FOREIGN KEY (org_id, department_id) REFERENCES departments (org_id, id)
);

CREATE TRIGGER teams_updated_at BEFORE UPDATE ON teams
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE team_members (
    org_id      uuid NOT NULL,
    team_id     uuid NOT NULL,
    user_id     uuid NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id),
    FOREIGN KEY (org_id, team_id) REFERENCES teams (org_id, id) ON DELETE CASCADE,
    
    FOREIGN KEY (org_id, user_id) REFERENCES memberships (org_id, user_id) ON DELETE CASCADE
);

CREATE INDEX team_members_user_id_idx ON team_members (org_id, user_id);


CREATE TABLE queues (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations (id),
    workspace_id uuid NOT NULL,
    team_id      uuid,
    name         text NOT NULL CHECK (length(trim(name)) > 0),
    
    criteria     jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(criteria) = 'object'),
    position     integer NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    UNIQUE (workspace_id, name),
    FOREIGN KEY (org_id, workspace_id) REFERENCES workspaces (org_id, id),
    FOREIGN KEY (org_id, team_id) REFERENCES teams (org_id, id)
);

CREATE TRIGGER queues_updated_at BEFORE UPDATE ON queues
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
