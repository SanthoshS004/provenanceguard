"""Role-Based Access Control (RBAC) Module for ProvenanceGuard.

Defines standard roles, granular permissions, role-permission matrix,
credential scope intersection semantics, and role delegation hierarchy.
"""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    """Standard system roles."""

    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    DEVELOPER = "DEVELOPER"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"
    CI_SERVICE = "CI_SERVICE"


class Permission(str, Enum):
    """Granular action permissions across API resources."""

    VERIFICATION_CREATE = "VERIFICATION_CREATE"
    VERIFICATION_READ = "VERIFICATION_READ"
    POLICY_MANAGE = "POLICY_MANAGE"
    AUDIT_READ = "AUDIT_READ"
    API_KEY_MANAGE = "API_KEY_MANAGE"
    ORG_ADMIN = "ORG_ADMIN"


# Base Role Permissions Matrix
ROLE_PERMISSIONS_MAP: dict[Role, set[Permission]] = {
    Role.ADMIN: {
        Permission.VERIFICATION_CREATE,
        Permission.VERIFICATION_READ,
        Permission.POLICY_MANAGE,
        Permission.AUDIT_READ,
        Permission.API_KEY_MANAGE,
        Permission.ORG_ADMIN,
    },
    Role.SECURITY_ANALYST: {
        Permission.VERIFICATION_CREATE,
        Permission.VERIFICATION_READ,
        Permission.POLICY_MANAGE,
        Permission.AUDIT_READ,
        Permission.API_KEY_MANAGE,
    },
    Role.DEVELOPER: {
        Permission.VERIFICATION_CREATE,
        Permission.VERIFICATION_READ,
    },
    Role.AUDITOR: {
        Permission.VERIFICATION_READ,
        Permission.AUDIT_READ,
    },
    Role.VIEWER: {
        Permission.VERIFICATION_READ,
    },
    Role.CI_SERVICE: {
        Permission.VERIFICATION_CREATE,
        Permission.VERIFICATION_READ,
    },
}

# Role Delegation Privilege Limits (which roles a given role is allowed to issue for API keys)
ROLE_DELEGATION_MAP: dict[Role, set[Role]] = {
    Role.ADMIN: {
        Role.ADMIN,
        Role.SECURITY_ANALYST,
        Role.DEVELOPER,
        Role.AUDITOR,
        Role.VIEWER,
        Role.CI_SERVICE,
    },
    Role.SECURITY_ANALYST: {
        Role.SECURITY_ANALYST,
        Role.DEVELOPER,
        Role.AUDITOR,
        Role.VIEWER,
        Role.CI_SERVICE,
    },
    Role.DEVELOPER: set(),
    Role.AUDITOR: set(),
    Role.VIEWER: set(),
    Role.CI_SERVICE: set(),
}


def get_effective_permissions(role: Role | str, scopes: list[str] | None = None) -> set[Permission]:
    """Calculates effective permissions as: Role Permissions ∩ Credential Scopes.

    Credential scopes can ONLY restrict permissions; they NEVER expand role privileges.
    If scopes is empty or contains '*', full role permissions are preserved.
    """
    try:
        role_enum = Role(role)
    except ValueError:
        return set()

    base_perms = ROLE_PERMISSIONS_MAP.get(role_enum, set())

    if not scopes or "*" in scopes or "full_access" in scopes:
        return set(base_perms)

    # Convert string scopes to Permission enums
    granted_scopes: set[Permission] = set()
    for s in scopes:
        try:
            granted_scopes.add(Permission(s))
        except ValueError:
            pass

    # Intersection formula: Effective = Role Permissions ∩ Credential Scopes
    return base_perms & granted_scopes


def can_delegate_role(issuer_role: Role | str, target_role: Role | str) -> bool:
    """Checks whether issuer_role is authorized to mint an API key for target_role."""
    try:
        issuer_enum = Role(issuer_role)
        target_enum = Role(target_role)
    except ValueError:
        return False

    allowed_target_roles = ROLE_DELEGATION_MAP.get(issuer_enum, set())
    return target_enum in allowed_target_roles
