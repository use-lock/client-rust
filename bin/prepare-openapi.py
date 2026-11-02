#!/usr/bin/env python3
"""Prepares Lock's OpenAPI specs for the generator.

Reads openapi/spec/{admin,auth,management}.json and openapi/operations.json and writes
{Admin,Auth,Management}.json into the directory given as the first argument: public operation
names and tags, pruned components and readable model names.
"""
import json
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
out = Path(sys.argv[1]) if len(sys.argv) > 1 else root / ".cache"
operations = json.loads((root / "openapi/operations.json").read_text())

RENAMES = {
    "OAuthClientRegistration": "ClientRegistrationRequest",
    "OAuthRegisteredClient": "RegisteredClient",
    "OAuthTokenResponse": "TokenResponse",
    "OAuthIntrospection": "TokenIntrospection",
    "OAuthProtectedResource": "ProtectedResourceMetadata",
    "OidcProviderMetadata": "ProviderMetadata",
    "OidcJwks": "JsonWebKeySet",
    "OidcUserinfo": "UserInfo",
}


def title_responses(operation):
    for status, response in operation["responses"].items():
        schema = response.get("content", {}).get("application/json", {}).get("schema", {})
        props = schema.get("properties")
        if not props:
            continue
        if "items" in props.get("data", {}) and "$ref" in props["data"]["items"]:
            model = props["data"]["items"]["$ref"].rsplit("/", 1)[1]
            schema["title"] = re.sub(r"Data$", "", model) + "Collection"
            props.get("links", {}).get("items", {})["title"] = "PaginationLink"
            props.get("meta", {})["title"] = "PaginationMeta"
        elif "$ref" in props.get("data", {}):
            schema["title"] = re.sub(r"Data$", "", props["data"]["$ref"].rsplit("/", 1)[1]) + "Response"
        elif "errors" in props:
            schema["title"] = "ValidationError"
        elif "error" in props:
            schema["title"] = "AuthorizationError" if str(status) == "403" else "AuthenticationError"
        elif "message" in props:
            schema["title"] = "ErrorResponse"


def refs(value, found):
    """Collects the component references below value, following them transitively."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str) and child.startswith("#/components/"):
                found.add(child)
            else:
                refs(child, found)
    elif isinstance(value, list):
        for child in value:
            refs(child, found)


def rename_refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str) and child.startswith("#/components/schemas/"):
                name = child.rsplit("/", 1)[1]
                value[key] = "#/components/schemas/" + RENAMES.get(name, name)
            else:
                rename_refs(child)
    elif isinstance(value, list):
        for child in value:
            rename_refs(child)


def simplify_resource(value):
    """The generator cannot render a string-or-array `oneOf`; a single string is what clients send."""
    if isinstance(value, dict):
        options = value.get("oneOf")
        if isinstance(options, list) and [o.get("type") for o in options if isinstance(o, dict)] == ["string", "array"]:
            del value["oneOf"]
            value["type"] = "string"
        for child in value.values():
            simplify_resource(child)
    elif isinstance(value, list):
        for child in value:
            simplify_resource(child)


for group in ("Admin", "Auth", "Management"):
    spec = json.loads((root / f"openapi/spec/{group.lower()}.json").read_text())
    document = {k: v for k, v in spec.items() if k != "paths"}
    document["servers"] = [{"url": "https://lock.example" if group == "Auth" else "https://lock.example/api"}]
    document["paths"] = {}

    for path, path_operations in spec["paths"].items():
        for method, operation in path_operations.items():
            if not isinstance(operation, dict):
                document["paths"].setdefault(path, {})[method] = operation
                continue
            for key in ("servers", "x-internal", "x-group"):
                operation.pop(key, None)
            op_id = operation["operationId"]
            if op_id not in operations:
                sys.exit(f"Missing public API name for {op_id} in openapi/operations.json")
            if operations[op_id] is None:
                continue
            tag, name = operations[op_id]
            operation["tags"] = [tag]
            operation["operationId"] = name
            title_responses(operation)
            document["paths"].setdefault(path, {})[method] = operation

    found: set[str] = set()
    pending = [document["paths"]]
    while pending:
        before = set(found)
        refs(pending.pop(), found)
        for ref in found - before:
            _, _, kind, name = ref.split("/")
            pending.append(spec["components"][kind][name])

    components = {}
    for ref in sorted(found):
        _, _, kind, name = ref.split("/")
        components.setdefault(kind, {})[name] = spec["components"][kind][name]
    if "OidcJwks" in components.get("schemas", {}):
        components["schemas"]["OidcJwks"]["properties"]["keys"]["items"]["title"] = "JsonWebKey"
    for kind in ("schemas",):
        components[kind] = {RENAMES.get(n, n): s for n, s in components.get(kind, {}).items()}
    for name, response in components.get("responses", {}).items():
        title = {"ValidationException": "ValidationError", "ModelNotFoundException": "NotFoundError"}.get(name, name)
        response["content"]["application/json"]["schema"]["title"] = title
    if "securitySchemes" in spec.get("components", {}):
        components["securitySchemes"] = spec["components"]["securitySchemes"]
    document["components"] = components
    rename_refs(document)
    simplify_resource(document)

    (out / f"{group}.json").write_text(json.dumps(document, indent=2) + "\n")
