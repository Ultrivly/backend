



CREATE UNIQUE INDEX roles_name_key ON roles (org_id, lower(name));


CREATE INDEX roles_org_idx ON roles (org_id, is_builtin DESC, name);
