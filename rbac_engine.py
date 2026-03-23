"""
rbac_engine.py — Azure RBAC Evaluation Engine

Azure RBAC differs significantly from AWS IAM. Understanding these differences
is critical for the AZ-104 exam.

AWS IAM vs Azure RBAC key differences:
  - Azure: additive (access = union of all matching role assignments)
  - AWS: explicit Deny always overrides Allow
  - Azure RBAC: scope inheritance flows DOWN the hierarchy
  - Azure: roles are assigned at a scope (not policies attached to principals)
  - Azure: NotActions removes from Actions (not a Deny — a different concept)

Azure RBAC Evaluation Logic:
  1. Collect all role assignments for the principal (direct + via groups)
  2. Filter to assignments that apply at or above the target scope (inheritance)
  3. For each matching assignment, collect Actions (minus NotActions)
  4. If ANY matching assignment grants the requested action → ALLOW
  5. Check for Deny Assignments (rare but override everything)
  6. Default: DENY if no Allow found

Scope Hierarchy (broader → narrower):
  ManagementGroup > Subscription > ResourceGroup > Resource
  An assignment at a broader scope applies to all narrower scopes within it.

Reference:
  https://learn.microsoft.com/en-us/azure/role-based-access-control/overview
"""

import fnmatch
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class RbacEvaluationStep:
    """One step in the RBAC evaluation trace."""
    assignment_id:   int
    role_name:       str
    principal_name:  str
    scope_level:     str
    scope_name:      str
    action_matched:  str
    outcome:         str    # "MATCHED_ALLOW" | "NO_MATCH" | "BLOCKED_BY_NOT_ACTION"
    reason:          str


@dataclass
class RbacEvaluationResult:
    """The final result of an Azure RBAC access check."""
    decision:        str                          # "ALLOW" or "DENY"
    reason:          str
    matching_role:   Optional[str] = None         # role name that granted access
    matching_scope:  Optional[str] = None         # scope where access was granted
    steps:           List[RbacEvaluationStep] = field(default_factory=list)

    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"


# ---------------------------------------------------------------------------
# Scope hierarchy helpers
# ---------------------------------------------------------------------------

# Scope levels ordered from broadest to narrowest
SCOPE_ORDER = ["ManagementGroup", "Subscription", "ResourceGroup", "Resource"]


def _scope_covers_target(assignment_scope_level: str, target_scope_level: str) -> bool:
    """
    Check if an assignment at `assignment_scope_level` covers `target_scope_level`.
    Azure RBAC uses INHERITANCE: broader scopes cover narrower scopes.

    Example: An assignment at Subscription scope covers ResourceGroup and Resource.
    Example: An assignment at ResourceGroup does NOT cover the parent Subscription.
    """
    try:
        assign_idx = SCOPE_ORDER.index(assignment_scope_level)
        target_idx = SCOPE_ORDER.index(target_scope_level)
        return assign_idx <= target_idx   # broader or same level covers target
    except ValueError:
        return False


def _assignment_applies_to_resource(assignment, target_rg=None, target_sub=None,
                                     target_mg=None, target_resource=None) -> bool:
    """
    Determine if a RoleAssignment applies given the target resource context.
    An assignment applies if its scope is at or above the target.
    """
    level = assignment.scope_level

    if level == "ManagementGroup":
        if target_mg and assignment.management_group_id == target_mg.id:
            return True
        if target_sub and target_sub.management_group_id == assignment.management_group_id:
            return True
        if target_rg and target_rg.subscription and target_rg.subscription.management_group_id == assignment.management_group_id:
            return True
        if target_resource and target_resource.resource_group and target_resource.resource_group.subscription and \
           target_resource.resource_group.subscription.management_group_id == assignment.management_group_id:
            return True

    elif level == "Subscription":
        if target_sub and assignment.subscription_id == target_sub.id:
            return True
        if target_rg and assignment.subscription_id == target_rg.subscription_id:
            return True
        if target_resource and target_resource.resource_group and \
           assignment.subscription_id == target_resource.resource_group.subscription_id:
            return True

    elif level == "ResourceGroup":
        if target_rg and assignment.resource_group_id == target_rg.id:
            return True
        if target_resource and assignment.resource_group_id == target_resource.resource_group_id:
            return True

    elif level == "Resource":
        if target_resource and assignment.resource_id == target_resource.id:
            return True

    return False


# ---------------------------------------------------------------------------
# Action matching (wildcard support)
# ---------------------------------------------------------------------------

def _action_matches(pattern: str, action: str) -> bool:
    """
    Azure RBAC uses case-insensitive wildcard matching for actions.
    Examples:
      "Microsoft.Compute/*"                    matches "Microsoft.Compute/virtualMachines/read"
      "Microsoft.Storage/storageAccounts/read" matches "Microsoft.Storage/storageAccounts/read"
      "*"                                      matches anything
    """
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def _action_in_list(action: str, action_patterns: list) -> bool:
    """Check if action matches any pattern in a list."""
    return any(_action_matches(p, action) for p in action_patterns)


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------

def evaluate_access(principal, action: str, target_scope: dict) -> RbacEvaluationResult:
    """
    Evaluate whether a principal has access to perform `action` at the given scope.

    Args:
        principal:    EntraUser, EntraGroup, or ServicePrincipal model instance
        action:       Azure operation e.g. "Microsoft.Compute/virtualMachines/start/action"
        target_scope: dict with keys: resource_group (optional), subscription (optional),
                      management_group (optional), resource (optional)

    Returns:
        RbacEvaluationResult
    """
    from models import EntraUser, EntraGroup, ServicePrincipal

    steps: List[RbacEvaluationStep] = []

    # Collect all applicable role assignments
    if isinstance(principal, EntraUser):
        all_assignments = principal.all_role_assignments()
        principal_label = principal.display_name
    elif isinstance(principal, EntraGroup):
        all_assignments = list(principal.role_assignments)
        principal_label = principal.display_name
    elif isinstance(principal, ServicePrincipal):
        all_assignments = list(principal.role_assignments)
        principal_label = principal.display_name
    else:
        return RbacEvaluationResult(
            decision="DENY",
            reason="Unknown principal type — cannot evaluate access.",
        )

    target_rg       = target_scope.get("resource_group")
    target_sub      = target_scope.get("subscription")
    target_mg       = target_scope.get("management_group")
    target_resource = target_scope.get("resource")

    # Determine target scope level
    if target_resource:
        target_level = "Resource"
    elif target_rg:
        target_level = "ResourceGroup"
    elif target_sub:
        target_level = "Subscription"
    elif target_mg:
        target_level = "ManagementGroup"
    else:
        return RbacEvaluationResult(
            decision="DENY",
            reason="No target scope specified.",
        )

    # Evaluate each role assignment
    for assignment in all_assignments:
        role = assignment.role_definition

        # Check if this assignment's scope covers the target
        if not _scope_covers_target(assignment.scope_level, target_level):
            step = RbacEvaluationStep(
                assignment_id=assignment.id,
                role_name=role.name,
                principal_name=principal_label,
                scope_level=assignment.scope_level,
                scope_name=assignment.scope_name,
                action_matched=action,
                outcome="NO_MATCH",
                reason=(
                    f"Assignment scope '{assignment.scope_level}' is narrower than "
                    f"target '{target_level}' — does not apply (no upward inheritance)."
                ),
            )
            steps.append(step)
            continue

        # Check if this assignment applies to the specific scope chain
        if not _assignment_applies_to_resource(assignment, target_rg, target_sub, target_mg, target_resource):
            step = RbacEvaluationStep(
                assignment_id=assignment.id,
                role_name=role.name,
                principal_name=principal_label,
                scope_level=assignment.scope_level,
                scope_name=assignment.scope_name,
                action_matched=action,
                outcome="NO_MATCH",
                reason=(
                    f"Assignment at '{assignment.scope_name}' is in a different "
                    f"scope chain — does not apply to the target."
                ),
            )
            steps.append(step)
            continue

        # Check Actions
        actions_list      = role.actions_list()
        not_actions_list  = role.not_actions_list()

        action_granted   = _action_in_list(action, actions_list)
        action_excluded  = _action_in_list(action, not_actions_list)

        if action_granted and not action_excluded:
            step = RbacEvaluationStep(
                assignment_id=assignment.id,
                role_name=role.name,
                principal_name=principal_label,
                scope_level=assignment.scope_level,
                scope_name=assignment.scope_name,
                action_matched=action,
                outcome="MATCHED_ALLOW",
                reason=(
                    f"Role '{role.name}' grants '{action}' via Actions at scope "
                    f"'{assignment.scope_name}' ({assignment.scope_level}). "
                    f"Scope inheritance applies — this assignment covers the target."
                ),
            )
            steps.append(step)
            return RbacEvaluationResult(
                decision="ALLOW",
                reason=step.reason,
                matching_role=role.name,
                matching_scope=assignment.scope_name,
                steps=steps,
            )
        elif action_granted and action_excluded:
            step = RbacEvaluationStep(
                assignment_id=assignment.id,
                role_name=role.name,
                principal_name=principal_label,
                scope_level=assignment.scope_level,
                scope_name=assignment.scope_name,
                action_matched=action,
                outcome="BLOCKED_BY_NOT_ACTION",
                reason=(
                    f"Role '{role.name}' would grant '{action}' via Actions, BUT "
                    f"it is removed by NotActions. Note: NotActions is NOT a Deny — "
                    f"another role assignment could still grant this action."
                ),
            )
            steps.append(step)
        else:
            step = RbacEvaluationStep(
                assignment_id=assignment.id,
                role_name=role.name,
                principal_name=principal_label,
                scope_level=assignment.scope_level,
                scope_name=assignment.scope_name,
                action_matched=action,
                outcome="NO_MATCH",
                reason=(
                    f"Role '{role.name}' at scope '{assignment.scope_name}' does not "
                    f"grant '{action}'. Checked {len(actions_list)} action pattern(s)."
                ),
            )
            steps.append(step)

    # No assignment granted access
    reason = (
        f"No role assignment grants '{action}' to '{principal_label}' "
        f"at or above the target scope. Azure RBAC defaults to DENY."
    )
    if not all_assignments:
        reason = (
            f"'{principal_label}' has no role assignments. "
            f"Without an explicit Allow, all access is denied by default."
        )

    return RbacEvaluationResult(
        decision="DENY",
        reason=reason,
        steps=steps,
    )


# ---------------------------------------------------------------------------
# Role definition health checks
# ---------------------------------------------------------------------------

def check_role_health(role) -> List[str]:
    """
    Check a custom role definition for common security issues.
    Maps to real Azure Advisor and Microsoft security recommendations.
    """
    warnings = []
    actions     = role.actions_list()
    not_actions = role.not_actions_list()

    if "*" in actions:
        warnings.append(
            "Actions contains '*' — this grants FULL control over all Azure resources. "
            "Only built-in Owner role should have this. Custom roles should be scoped to "
            "specific namespaces (e.g., 'Microsoft.Compute/*')."
        )

    broad_actions = [a for a in actions if a.endswith("/*") and not a.startswith("Microsoft.") == False]
    for a in broad_actions:
        service = a.split("/")[0]
        warnings.append(
            f"Action '{a}' grants ALL operations on {service}. "
            f"Consider narrowing to only the specific operations required (least privilege)."
        )

    write_actions = [a for a in actions if "write" in a.lower() or "delete" in a.lower()]
    auth_not_excluded = not any("Microsoft.Authorization" in na for na in not_actions)
    if write_actions and auth_not_excluded and role.role_type == "CustomRole":
        warnings.append(
            "This role has write/delete actions but does not exclude 'Microsoft.Authorization/*' "
            "in NotActions. Consider adding it to prevent privilege escalation."
        )

    return warnings
