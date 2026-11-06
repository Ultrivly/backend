import json
import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "src/http/openapi.json")
SRC = os.path.join(ROOT, "src")


def read(path):
    with open(path) as f:
        return f.read()


all_sources = {}
for dirpath, _, files in os.walk(SRC):
    for name in files:
        if name.endswith(".rs"):
            p = os.path.join(dirpath, name)
            all_sources[p] = read(p)

routes_src = read(os.path.join(SRC, "http/routes/mod.rs")).split("#[cfg(test)]")[0]


def balanced(text, start):
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("unbalanced")


routes = []
for m in re.finditer(r"\.route\(", routes_src):
    end = balanced(routes_src, m.end() - 1)
    body = routes_src[m.end():end]
    path = re.search(r'"([^"]+)"', body).group(1)
    chain = body[body.index('"', body.index('"') + 1) + 1:]
    for hm in re.finditer(r"\b(get|post|put|patch|delete|options)\(", chain):
        inner_end = balanced(chain, hm.end() - 1)
        target = chain[hm.end():inner_end].strip()
        routes.append((path, hm.group(1), target))

structs = {}
enums = {}
for p, s in all_sources.items():
    for m in re.finditer(r"((?:#\[[^\]]*\]\s*)*)pub (struct|enum) (\w+)(<[^>]*>)?\s*\{", s):
        start = m.end() - 1
        depth = 0
        for i in range(start, len(s)):
            if s[i] == "{":
                depth += 1
            elif s[i] == "}":
                depth -= 1
                if depth == 0:
                    break
        (structs if m.group(2) == "struct" else enums).setdefault(m.group(3), (m.group(1), s[start + 1:i], p))

components = {}


def serde_attr(attrs, key):
    m = re.search(r'#\[serde\([^\]]*\b' + key + r'\s*=\s*"([^"]+)"', attrs)
    return m.group(1) if m else None


def schema_for(ty, depth=0):
    ty = ty.strip()
    ty = re.sub(r"^&'?\w*\s*", "", ty) if ty.startswith("&") else ty
    m = re.match(r"^(?:std::option::)?Option<(.+)>$", ty)
    if m:
        inner = schema_for(m.group(1), depth)
        return {**inner, "nullable": True} if "$ref" not in inner else {"allOf": [inner], "nullable": True}
    m = re.match(r"^Vec<(.+)>$", ty)
    if m:
        return {"type": "array", "items": schema_for(m.group(1), depth)}
    m = re.match(r"^\[(.+)\]$", ty)
    if m:
        return {"type": "array", "items": schema_for(m.group(1), depth)}
    base = ty.split("::")[-1]
    if base in ("String", "str", "Cow<'_, str>"):
        return {"type": "string"}
    if base == "Uuid":
        return {"type": "string", "format": "uuid"}
    if base in ("i16", "i32", "u16", "u32"):
        return {"type": "integer", "format": "int32"}
    if base in ("i64", "u64", "usize"):
        return {"type": "integer", "format": "int64"}
    if base in ("f32", "f64"):
        return {"type": "number"}
    if base == "bool":
        return {"type": "boolean"}
    if base.startswith("DateTime"):
        return {"type": "string", "format": "date-time"}
    if base == "NaiveDate":
        return {"type": "string", "format": "date"}
    if base in ("Value",):
        return {}
    if base.startswith("Map<") or base.startswith("HashMap<") or base.startswith("BTreeMap<"):
        return {"type": "object", "additionalProperties": True}
    name = re.sub(r"<.*>", "", base)
    if name in structs or name in enums:
        if depth < 6:
            build_component(name, depth + 1)
        return {"$ref": f"#/components/schemas/{name}"}
    return {"description": f"{ty}"}


def split_fields(body):
    fields, depth, cur = [], 0, ""
    for ch in body:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        if ch == "," and depth == 0:
            fields.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        fields.append(cur)
    return fields


def struct_schema(attrs, body, depth):
    rename_all = serde_attr(attrs, "rename_all")
    props, required = {}, []
    deny = "deny_unknown_fields" in attrs
    for raw in split_fields(body):
        field_attrs = " ".join(re.findall(r"#\[[^\]]*\]", raw))
        text = re.sub(r"#\[[^\]]*\]", "", raw)
        text = re.sub(r"//.*", "", text).strip()
        m = re.match(r"^(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*(.+)$", text, re.S)
        if not m:
            continue
        name, ty = m.group(1), " ".join(m.group(2).split())
        if re.search(r"serde\([^)]*\bskip\b", field_attrs):
            continue
        if re.search(r"serde\([^)]*\bflatten\b", field_attrs):
            inner = schema_for(ty, depth)
            if "$ref" in inner:
                ref = inner["$ref"].split("/")[-1]
                comp = components.get(ref, {})
                props.update(comp.get("properties", {}))
            continue
        rename = serde_attr(field_attrs, "rename")
        key = rename or (name if rename_all != "camelCase" else re.sub(r"_(\w)", lambda x: x.group(1).upper(), name))
        props[key] = schema_for(ty, depth)
        optional = ty.startswith("Option<") or re.search(r"serde\([^)]*\bdefault\b", field_attrs) or re.search(r"serde\([^)]*\bdefault\b", attrs)
        if not optional:
            required.append(key)
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    if deny:
        schema["additionalProperties"] = False
    return schema


def enum_schema(attrs, body, depth):
    tag = serde_attr(attrs, "tag")
    rename_all = serde_attr(attrs, "rename_all")

    def case(name):
        if rename_all == "snake_case":
            return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
        if rename_all == "lowercase":
            return name.lower()
        return name

    variants = []
    for raw in split_fields(body):
        text = re.sub(r"#\[[^\]]*\]", "", raw)
        text = re.sub(r"//.*", "", text).strip()
        if not text:
            continue
        m = re.match(r"^(\w+)\s*(\{(.*)\}|\((.*)\))?$", text, re.S)
        if not m:
            continue
        vname = m.group(1)
        rename = serde_attr(raw, "rename")
        value = rename or case(vname)
        if m.group(3) is not None:
            s = struct_schema("", m.group(3), depth)
            if tag:
                s["properties"] = {tag: {"type": "string", "enum": [value]}, **s["properties"]}
                s.setdefault("required", []).insert(0, tag)
            variants.append(s)
        else:
            variants.append({"type": "string", "enum": [value]} if not tag else {"type": "object", "properties": {tag: {"type": "string", "enum": [value]}}, "required": [tag]})
    if all(v.get("type") == "string" and "enum" in v for v in variants):
        return {"type": "string", "enum": [v["enum"][0] for v in variants]}
    return {"oneOf": variants}


def build_component(name, depth=0):
    if name in components:
        return
    components[name] = {}
    if name in structs:
        attrs, body, _ = structs[name]
        components[name] = struct_schema(attrs, body, depth)
    else:
        attrs, body, _ = enums[name]
        components[name] = enum_schema(attrs, body, depth)


def find_handler(target):
    if "::" not in target or not re.match(r"^\w+::\w+$", target):
        return None, None
    module, fn = target.split("::", 1)
    path = os.path.join(SRC, "http/routes", module + ".rs")
    s = all_sources[path]
    m = re.search(r"pub async fn " + re.escape(fn) + r"\s*\(", s)
    sig_end = balanced(s, m.end() - 1)
    sig = s[m.end():sig_end]
    body_start = s.index("{", sig_end)
    depth = 0
    for i in range(body_start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                break
    return sig, s[body_start:i]


def words(fn):
    w = fn.replace("_", " ")
    return w[:1].upper() + w[1:]


TAGS = [
    ("/api/v1/auth", "Authentication"), ("/auth/", "Single sign-on"), ("/sign-in", "Single sign-on"),
    ("/api/v1/me", "Account"), ("/api/v1/invitations", "Organizations"), ("/api/v1/permissions", "Organizations"),
    ("/api/v1/portal", "Requester portal"), ("/api/v1/inbound", "Channels"), ("/api/v1/chat", "Channels"),
    ("/api/v1/mail", "Email"), ("/api/v1/help", "Knowledge"), ("/api/v1/plugins", "Plugins"),
    ("/healthz", "Operations"), ("/readyz", "Operations"),
]
ORG_TAGS = {
    "invitations": "Organizations", "workspaces": "Organizations", "members": "Organizations", "roles": "Organizations",
    "delete": "Organizations", "restore": "Organizations", "sso-connections": "Single sign-on", "audit-events": "Audit",
    "api-credentials": "Integrations", "departments": "Routing", "teams": "Routing", "queues": "Routing",
    "case-settings": "Case configuration", "statuses": "Case configuration", "priorities": "Case configuration",
    "custom-fields": "Case configuration", "sla-policies": "Case configuration", "views": "Cases",
    "contacts": "Contacts", "cases": "Cases", "attachments": "Cases", "channels": "Channels",
    "webhooks": "Integrations", "webhook-deliveries": "Integrations", "workflows": "Workflows", "ai": "AI",
    "jobs": "Operations", "exports": "Data export", "mail-domains": "Email", "plugins": "Plugins",
    "reports": "Reporting", "kb": "Knowledge",
}


def tag_for(path):
    m = re.match(r"^/api/v1/orgs/\{org_id\}/([^/]+)", path)
    if m:
        if path.endswith("/assist"):
            return "AI"
        return ORG_TAGS.get(m.group(1), "Organizations")
    if path.startswith("/api/v1/orgs"):
        return "Organizations"
    for prefix, tag in TAGS:
        if path.startswith(prefix):
            return tag
    return "Other"


paths = {}
seen_ids = set()
for path, method, target in routes:
    sig, body = find_handler(target)
    op = {"tags": [tag_for(path)]}
    params = [{"name": p, "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"} if p.endswith("id") else {"type": "string"}} for p in re.findall(r"\{(\w+)\}", path)]
    security = []
    responses = {}
    if sig is None:
        op["summary"] = "Redirect to the sign-in page"
        op["operationId"] = "saml_slo_redirect"
        responses["303"] = {"description": "Redirect"}
    else:
        fn = target.split("::")[1]
        op["operationId"] = fn
        op["summary"] = words(fn)
        if "caller: Caller" in sig:
            security = [{"session": []}, {"apiKey": []}]
        elif re.search(r"Authenticated|session: Session|PortalSession|Portal", sig):
            security = [{"session": []}]
        q = re.search(r"Query\((?:\w+)\):\s*Query<([\w:]+)>", sig)
        if q:
            qname = q.group(1).split("::")[-1]
            if qname in structs:
                build_component(qname)
                for k, v in components[qname].get("properties", {}).items():
                    v2 = dict(v)
                    v2.pop("nullable", None)
                    params.append({"name": k, "in": "query", "required": False, "schema": v2 if v2 else {"type": "string"}})
            elif "HashMap" in qname:
                pass
        j = re.search(r"Json\(\w+\):\s*Json<([\w:]+)>", sig) or re.search(r"Option<Json<([\w:]+)>>", sig)
        if j:
            jname = j.group(1).split("::")[-1]
            build_component(jname)
            op["requestBody"] = {"required": "Option<Json" not in sig, "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{jname}"}}}}
        elif re.search(r"body:\s*Bytes", sig):
            ctype = "application/octet-stream" if "attachments" in path else "application/json"
            op["requestBody"] = {"required": True, "content": {ctype: {"schema": {"type": "string", "format": "binary"} if ctype != "application/json" else {"type": "object"}}}}
        elif re.search(r"Form<", sig):
            op["requestBody"] = {"required": True, "content": {"application/x-www-form-urlencoded": {"schema": {"type": "object"}}}}
        status = "200"
        for code, name in (("201", "CREATED"), ("202", "ACCEPTED"), ("204", "NO_CONTENT"), ("303", "SEE_OTHER")):
            if f"StatusCode::{name}" in body:
                status = code
                break
        if "Redirect::" in body and status == "200":
            status = "303"
        desc = {"200": "OK", "201": "Created", "202": "Accepted", "204": "No content", "303": "Redirect"}[status]
        if "Paged::new" in body:
            responses[status] = {"description": desc, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Page"}}}}
        elif status in ("204", "303"):
            responses[status] = {"description": desc}
        elif "application/zip" in body:
            responses[status] = {"description": desc, "content": {"application/zip": {"schema": {"type": "string", "format": "binary"}}}}
        elif "download_attachment" in fn:
            responses[status] = {"description": desc, "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}
        else:
            keys = re.findall(r'json!\(\{\s*"(\w+)"', body)
            schema = {"type": "object"}
            if keys:
                schema["properties"] = {k: {} for k in dict.fromkeys(keys)}
            responses[status] = {"description": desc, "content": {"application/json": {"schema": schema}}}
        if "ultrivly-signature" in body or "signature(&headers)" in body:
            params.append({"name": "ultrivly-signature", "in": "header", "required": True, "schema": {"type": "string"}, "description": "t=<unix seconds>,v1=<hex HMAC-SHA256 of \"<t>.<body>\"> using the shared secret"})
        if "chat_token" in body:
            security = [{"chatToken": []}]
    if params:
        op["parameters"] = params
    if security:
        op["security"] = security
    else:
        op["security"] = []
    for code, ref in (("400", "Error"), ("401", "Error"), ("403", "Error"), ("404", "Error"), ("409", "Error"), ("422", "Error"), ("429", "Error")):
        responses.setdefault(code, {"$ref": f"#/components/responses/Error"})
    op["responses"] = responses
    if method == "post" and path.startswith("/api/v1/orgs/{org_id}/"):
        op.setdefault("parameters", []).append({"$ref": "#/components/parameters/IdempotencyKey"})
    base_id = op["operationId"]
    if base_id in seen_ids:
        suffix = "_".join(seg for seg in path.split("/") if seg and not seg.startswith("{"))[-40:]
        op["operationId"] = f"{base_id}_{suffix}".replace("-", "_")
    seen_ids.add(op["operationId"])
    paths.setdefault(path, {})[method] = op

components.update({
    "Error": {
        "type": "object",
        "required": ["error"],
        "properties": {"error": {"type": "object", "required": ["code", "message"], "properties": {
            "code": {"type": "string"}, "message": {"type": "string"}, "field": {"type": "string"}}}},
    },
    "Page": {
        "type": "object",
        "required": ["data", "next_cursor"],
        "properties": {"data": {"type": "array", "items": {"type": "object"}}, "next_cursor": {"type": "string", "format": "uuid", "nullable": True}},
    },
})

doc = {
    "openapi": "3.0.3",
    "info": {
        "title": "Ultrivly API",
        "version": "1",
        "description": "Ultrivly helpdesk API. Organization routes accept a session cookie or a bearer API key. "
        "Lists use cursor pagination (limit 1-100, cursor = next_cursor from the previous page). "
        "Errors use the Error schema. POST requests under /api/v1/orgs/{org_id}/ accept an Idempotency-Key header. "
        "Every response carries an x-request-id header to quote in support requests.",
    },
    "servers": [{"url": "/"}],
    "tags": [{"name": t} for t in sorted({op["tags"][0] for ops in paths.values() for op in ops.values()})],
    "paths": dict(sorted(paths.items())),
    "components": {
        "securitySchemes": {
            "session": {"type": "apiKey", "in": "cookie", "name": "__Host-ultrivly_session", "description": "Browser session. State-changing requests must also pass the same-origin checks."},
            "apiKey": {"type": "http", "scheme": "bearer", "description": "API credential created under /api/v1/orgs/{org_id}/api-credentials."},
            "chatToken": {"type": "http", "scheme": "bearer", "description": "Conversation token returned when a chat starts."},
        },
        "parameters": {
            "IdempotencyKey": {"name": "Idempotency-Key", "in": "header", "required": False, "schema": {"type": "string", "maxLength": 255}, "description": "Repeat a request safely. Keys are kept for 24 hours per organization and caller."},
        },
        "responses": {
            "Error": {"description": "Error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
        },
        "schemas": dict(sorted(components.items())),
    },
}

with open(OUT, "w") as f:
    json.dump(doc, f, indent=1, sort_keys=False)
    f.write("\n")

ops = sum(len(v) for v in paths.values())
print(f"{len(paths)} paths, {ops} operations, {len(components)} schemas")
unknown = [k for k, v in components.items() if v == {}]
if unknown:
    print("components without a schema:", unknown)
