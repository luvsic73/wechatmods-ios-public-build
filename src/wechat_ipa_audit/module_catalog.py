from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any


_RISK_LEVELS = {"low", "medium", "high", "critical"}
_REQUIRED_FIELDS = {
    "id": str,
    "title": str,
    "group": str,
    "compatible_versions": list,
    "dependencies": list,
    "conflicts": list,
    "hooks": list,
    "risk": str,
    "risk_reasons": list,
    "enabled": bool,
}


def effective_activation_gate(module: dict[str, Any]) -> str:
    default_gate = (
        "component-repair-required"
        if module.get("runtime") == "feature-collection"
        else "ready"
    )
    return module.get("activation_gate", default_gate)


def validate_catalog(modules: list[dict[str, Any]]) -> list[str]:
    issues: list[str] = []
    by_id: dict[str, dict[str, Any]] = {}
    setters: dict[tuple[str, str], str] = {}
    for index, module in enumerate(modules):
        prefix = f"module[{index}]"
        for field, expected_type in _REQUIRED_FIELDS.items():
            if not isinstance(module.get(field), expected_type):
                issues.append(f"{prefix}:invalid_field:{field}")
        module_id = module.get("id")
        if not isinstance(module_id, str):
            continue
        if module_id in by_id:
            issues.append(f"{module_id}:duplicate_id")
        by_id[module_id] = module
        if module.get("enabled") is not False:
            issues.append(f"{module_id}:default_must_be_disabled")
        risk = module.get("risk")
        if risk not in _RISK_LEVELS:
            issues.append(f"{module_id}:invalid_risk:{risk}")
        if risk in {"high", "critical"} and not module.get("risk_reasons"):
            issues.append(f"{module_id}:missing_risk_reasons")
        hooks = module.get("hooks", [])
        if hooks and not isinstance(module.get("hook_owner"), str):
            issues.append(f"{module_id}:missing_hook_owner")
        runtime = module.get("runtime")
        if runtime == "feature-collection":
            for field in ("config_class", "shared_selector", "setter"):
                if not isinstance(module.get(field), str):
                    issues.append(f"{module_id}:missing_{field}")
            config_class = module.get("config_class")
            setter = module.get("setter")
            if isinstance(config_class, str) and isinstance(setter, str):
                key = (config_class, setter)
                if key in setters:
                    issues.append(f"{module_id}:duplicate_setter:{setters[key]}")
                setters[key] = module_id
    for module_id, module in by_id.items():
        for dependency in module.get("dependencies", []):
            if dependency not in by_id:
                issues.append(f"{module_id}:unknown_dependency:{dependency}")
        for conflict in module.get("conflicts", []):
            if conflict not in by_id:
                issues.append(f"{module_id}:unknown_conflict:{conflict}")
            elif module_id not in by_id[conflict].get("conflicts", []):
                issues.append(f"{module_id}:asymmetric_conflict:{conflict}")
    return sorted(set(issues))


def build_activation_plan(
    modules: list[dict[str, Any]],
    *,
    requested: Iterable[str],
    version: str,
) -> dict[str, Any]:
    by_id = {module["id"]: module for module in modules}
    requested_set = set(requested)
    blocked: dict[str, set[str]] = defaultdict(set)
    for module_id in requested_set:
        module = by_id.get(module_id)
        if module is None:
            blocked[module_id].add("unknown_module")
            continue
        if version not in module["compatible_versions"]:
            blocked[module_id].add(f"incompatible_version:{version}")
        activation_gate = effective_activation_gate(module)
        if activation_gate != "ready":
            blocked[module_id].add(f"activation_gate:{activation_gate}")
        for dependency in module["dependencies"]:
            if dependency not in requested_set:
                blocked[module_id].add(f"dependency_disabled:{dependency}")
        for conflict in module["conflicts"]:
            if conflict in requested_set:
                blocked[module_id].add(f"explicit_conflict:{conflict}")

    hook_users: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for module_id in requested_set:
        module = by_id.get(module_id)
        if module is None:
            continue
        owner = module.get("hook_owner", "")
        for hook in module["hooks"]:
            hook_users[hook].append((module_id, owner))
    for hook, users in hook_users.items():
        if len({owner for _, owner in users}) <= 1:
            continue
        for module_id, _ in users:
            blocked[module_id].add(f"hook_collision:{hook}")

    changed = True
    while changed:
        changed = False
        for module_id in requested_set - set(blocked):
            module = by_id.get(module_id)
            if module is None:
                continue
            for dependency in module["dependencies"]:
                if dependency in blocked:
                    blocked[module_id].add(f"dependency_blocked:{dependency}")
                    changed = True

    enabled = sorted(requested_set - set(blocked))
    risk_flags = {
        module_id: list(by_id[module_id]["risk_reasons"])
        for module_id in enabled
        if by_id[module_id]["risk"] in {"high", "critical"}
    }
    return {
        "enabled": enabled,
        "blocked": {
            module_id: sorted(reasons) for module_id, reasons in sorted(blocked.items())
        },
        "risk_flags": risk_flags,
    }
