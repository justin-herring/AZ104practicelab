"""
models.py — SQLAlchemy models for the AZ-104 Azure Practice Lab.

Mirrors the real Azure resource model:
  - Entra ID (Azure AD): Users, Groups, Service Principals
  - Resource Hierarchy: ManagementGroup > Subscription > ResourceGroup > Resource
  - Azure RBAC: RoleDefinition + RoleAssignment (Principal + Role + Scope)
  - Labs and Quiz for exam preparation
  - ActivityLog mirrors Azure Monitor Activity Log

Key Azure RBAC concepts implemented here:
  - Scope: The boundary at which a role applies. Assignments inherit DOWN the hierarchy.
  - Principal: Who gets access (User, Group, Service Principal, Managed Identity)
  - Role Definition: What permissions are granted (Actions, NotActions, DataActions)
  - Role Assignment: The binding of (Principal + Role + Scope)
"""

import json
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# ---------------------------------------------------------------------------
# Resource Hierarchy (Management Group > Subscription > Resource Group > Resource)
# ---------------------------------------------------------------------------

class ManagementGroup(db.Model):
    """
    Azure Management Groups provide a governance scope above subscriptions.
    All subscriptions within a management group inherit conditions applied to it.
    Root management group is at the top; can have child management groups.
    """
    __tablename__ = "management_groups"

    id           = db.Column(db.Integer, primary_key=True)
    name         = db.Column(db.String(64), unique=True, nullable=False)   # slug, e.g. "contoso-root"
    display_name = db.Column(db.String(128), nullable=False)
    parent_id    = db.Column(db.Integer, db.ForeignKey("management_groups.id"), nullable=True)
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    children      = db.relationship("ManagementGroup", backref=db.backref("parent", remote_side=[id]))
    subscriptions = db.relationship("Subscription", back_populates="management_group")
    role_assignments = db.relationship(
        "RoleAssignment", back_populates="mg_scope",
        foreign_keys="RoleAssignment.management_group_id"
    )

    @property
    def scope_id(self):
        return f"/providers/Microsoft.Management/managementGroups/{self.name}"

    def __repr__(self):
        return f"<ManagementGroup {self.display_name}>"


class Subscription(db.Model):
    """
    An Azure Subscription is a logical unit of Azure services linked to an Azure account.
    It's the primary billing boundary and a common RBAC scope.
    """
    __tablename__ = "subscriptions"

    id                  = db.Column(db.Integer, primary_key=True)
    name                = db.Column(db.String(128), nullable=False)
    subscription_id     = db.Column(db.String(36), unique=True, nullable=False)   # GUID
    management_group_id = db.Column(db.Integer, db.ForeignKey("management_groups.id"), nullable=True)
    state               = db.Column(db.String(16), default="Enabled")
    created_at          = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    management_group = db.relationship("ManagementGroup", back_populates="subscriptions")
    resource_groups  = db.relationship("ResourceGroup", back_populates="subscription")
    role_assignments = db.relationship(
        "RoleAssignment", back_populates="sub_scope",
        foreign_keys="RoleAssignment.subscription_id"
    )

    @property
    def scope_id(self):
        return f"/subscriptions/{self.subscription_id}"

    def __repr__(self):
        return f"<Subscription {self.name}>"


class ResourceGroup(db.Model):
    """
    A Resource Group is a container that holds related Azure resources.
    All resources in a group share the same lifecycle, permissions, and policies.
    Resource Groups are a very common RBAC assignment scope.
    """
    __tablename__ = "resource_groups"

    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(90), nullable=False)
    subscription_id = db.Column(db.Integer, db.ForeignKey("subscriptions.id"), nullable=False)
    location        = db.Column(db.String(32), nullable=False, default="eastus")
    tags            = db.Column(db.Text, nullable=True)   # JSON
    created_at      = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    subscription     = db.relationship("Subscription", back_populates="resource_groups")
    resources        = db.relationship("AzureResource", back_populates="resource_group")
    role_assignments = db.relationship(
        "RoleAssignment", back_populates="rg_scope",
        foreign_keys="RoleAssignment.resource_group_id"
    )

    @property
    def scope_id(self):
        sub = self.subscription
        return f"/subscriptions/{sub.subscription_id}/resourceGroups/{self.name}"

    def tags_parsed(self):
        try:
            return json.loads(self.tags) if self.tags else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    def __repr__(self):
        return f"<ResourceGroup {self.name}>"


class AzureResource(db.Model):
    """
    A concrete Azure resource (VM, Storage Account, VNet, etc.).
    Resource type follows the ARM namespace: Microsoft.Compute/virtualMachines
    """
    __tablename__ = "azure_resources"

    id                = db.Column(db.Integer, primary_key=True)
    name              = db.Column(db.String(128), nullable=False)
    resource_type     = db.Column(db.String(128), nullable=False)   # e.g. Microsoft.Compute/virtualMachines
    resource_group_id = db.Column(db.Integer, db.ForeignKey("resource_groups.id"), nullable=False)
    location          = db.Column(db.String(32), nullable=False)
    tags              = db.Column(db.Text, nullable=True)
    properties        = db.Column(db.Text, nullable=True)   # JSON for resource-specific props
    created_at        = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    resource_group   = db.relationship("ResourceGroup", back_populates="resources")
    role_assignments = db.relationship(
        "RoleAssignment", back_populates="resource_scope",
        foreign_keys="RoleAssignment.resource_id"
    )

    @property
    def type_icon(self):
        icons = {
            "Microsoft.Compute/virtualMachines": "bi-display",
            "Microsoft.Storage/storageAccounts": "bi-hdd",
            "Microsoft.Network/virtualNetworks": "bi-diagram-3",
            "Microsoft.Network/networkSecurityGroups": "bi-shield-lock",
            "Microsoft.Web/sites": "bi-globe",
            "Microsoft.Sql/servers": "bi-database",
            "Microsoft.KeyVault/vaults": "bi-key",
            "Microsoft.ContainerService/managedClusters": "bi-boxes",
        }
        return icons.get(self.resource_type, "bi-box")

    @property
    def type_short(self):
        return self.resource_type.split("/")[-1] if "/" in self.resource_type else self.resource_type

    def __repr__(self):
        return f"<AzureResource {self.name} ({self.resource_type})>"


# ---------------------------------------------------------------------------
# Entra ID (Azure Active Directory) Identities
# ---------------------------------------------------------------------------

user_group_memberships = db.Table(
    "user_group_memberships",
    db.Column("user_id",  db.Integer, db.ForeignKey("entra_users.id"),  primary_key=True),
    db.Column("group_id", db.Integer, db.ForeignKey("entra_groups.id"), primary_key=True),
)


class EntraUser(db.Model):
    """
    An Entra ID (Azure AD) user identity.
    Users authenticate with Microsoft accounts and can be assigned Azure RBAC roles.
    Best practice: Assign roles to groups rather than individual users.
    """
    __tablename__ = "entra_users"

    id              = db.Column(db.Integer, primary_key=True)
    display_name    = db.Column(db.String(128), nullable=False)
    upn             = db.Column(db.String(256), unique=True, nullable=False)   # user@contoso.com
    user_type       = db.Column(db.String(16), default="Member")               # Member or Guest
    account_enabled = db.Column(db.Boolean, default=True)
    mfa_enabled     = db.Column(db.Boolean, default=False)
    department      = db.Column(db.String(64), nullable=True)
    job_title       = db.Column(db.String(64), nullable=True)
    created_at      = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    groups           = db.relationship("EntraGroup", secondary=user_group_memberships, back_populates="members")
    role_assignments = db.relationship(
        "RoleAssignment", back_populates="user_principal",
        foreign_keys="RoleAssignment.user_id"
    )

    def all_role_assignments(self):
        """Return direct + group-inherited role assignments."""
        direct = list(self.role_assignments)
        via_group = [ra for g in self.groups for ra in g.role_assignments]
        return direct + via_group

    def __repr__(self):
        return f"<EntraUser {self.upn}>"


class EntraGroup(db.Model):
    """
    An Entra ID Security Group.
    Assigning roles to groups (rather than individual users) is best practice —
    it makes access management easier and reduces audit complexity.
    Microsoft 365 groups can also be role-assignable.
    """
    __tablename__ = "entra_groups"

    id                 = db.Column(db.Integer, primary_key=True)
    display_name       = db.Column(db.String(256), nullable=False)
    group_type         = db.Column(db.String(32), default="Security")   # Security or Microsoft365
    description        = db.Column(db.String(512), nullable=True)
    assignable_to_role = db.Column(db.Boolean, default=True)            # can this group be assigned RBAC roles?
    created_at         = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    members          = db.relationship("EntraUser", secondary=user_group_memberships, back_populates="groups")
    role_assignments = db.relationship(
        "RoleAssignment", back_populates="group_principal",
        foreign_keys="RoleAssignment.group_id"
    )

    def __repr__(self):
        return f"<EntraGroup {self.display_name}>"


class ServicePrincipal(db.Model):
    """
    A Service Principal is a security identity for applications or services.
    When you register an app in Entra ID, a Service Principal is created automatically.
    Managed Identities are special Service Principals managed by Azure — no credentials needed.
    """
    __tablename__ = "service_principals"

    id              = db.Column(db.Integer, primary_key=True)
    display_name    = db.Column(db.String(256), nullable=False)
    sp_type         = db.Column(db.String(32), default="Application")   # Application or ManagedIdentity
    app_id          = db.Column(db.String(36), unique=True, nullable=False)   # GUID (client ID)
    account_enabled = db.Column(db.Boolean, default=True)
    description     = db.Column(db.String(512), nullable=True)
    created_at      = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    role_assignments = db.relationship(
        "RoleAssignment", back_populates="sp_principal",
        foreign_keys="RoleAssignment.service_principal_id"
    )

    def __repr__(self):
        return f"<ServicePrincipal {self.display_name}>"


# ---------------------------------------------------------------------------
# Azure RBAC — Role Definitions and Assignments
# ---------------------------------------------------------------------------

class RoleDefinition(db.Model):
    """
    A Role Definition lists the set of permissions.
    Structure:
      Actions:       control-plane operations allowed (e.g. "Microsoft.Compute/virtualMachines/start/action")
      NotActions:    excluded from Actions (e.g. "Microsoft.Authorization/*/Delete")
      DataActions:   data-plane operations allowed (e.g. "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read")
      NotDataActions: excluded from DataActions

    Effective permissions = (Actions - NotActions) for control plane
                          + (DataActions - NotDataActions) for data plane

    Built-in roles: Owner, Contributor, Reader, User Access Administrator, and 100+ service-specific
    Custom roles: Defined per tenant or subscription with precise permission sets
    """
    __tablename__ = "role_definitions"

    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(128), unique=True, nullable=False)
    description     = db.Column(db.String(512), nullable=True)
    role_type       = db.Column(db.String(32), default="BuiltInRole")   # BuiltInRole or CustomRole
    actions         = db.Column(db.Text, nullable=False)       # JSON array
    not_actions     = db.Column(db.Text, default="[]")         # JSON array
    data_actions    = db.Column(db.Text, default="[]")         # JSON array
    not_data_actions = db.Column(db.Text, default="[]")        # JSON array

    role_assignments = db.relationship("RoleAssignment", back_populates="role_definition")

    def actions_list(self):
        try:
            return json.loads(self.actions)
        except (json.JSONDecodeError, TypeError):
            return []

    def not_actions_list(self):
        try:
            return json.loads(self.not_actions)
        except (json.JSONDecodeError, TypeError):
            return []

    def data_actions_list(self):
        try:
            return json.loads(self.data_actions)
        except (json.JSONDecodeError, TypeError):
            return []

    def not_data_actions_list(self):
        try:
            return json.loads(self.not_data_actions)
        except (json.JSONDecodeError, TypeError):
            return []

    def __repr__(self):
        return f"<RoleDefinition {self.name}>"


class RoleAssignment(db.Model):
    """
    A Role Assignment is the binding of:
      - WHO  (security principal: user, group, or service principal)
      - WHAT (role definition: what operations are allowed)
      - WHERE (scope: management group, subscription, resource group, or resource)

    Key rule: assignments are additive — a user's effective access is the UNION
    of all role assignments that apply to them at and above the target scope.
    Scope inheritance means an assignment at a subscription also applies to
    all resource groups and resources within it.
    """
    __tablename__ = "role_assignments"

    id                 = db.Column(db.Integer, primary_key=True)
    role_definition_id = db.Column(db.Integer, db.ForeignKey("role_definitions.id"), nullable=False)
    description        = db.Column(db.String(256), nullable=True)
    assigned_at        = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Principal — exactly one of these should be set
    user_id              = db.Column(db.Integer, db.ForeignKey("entra_users.id"), nullable=True)
    group_id             = db.Column(db.Integer, db.ForeignKey("entra_groups.id"), nullable=True)
    service_principal_id = db.Column(db.Integer, db.ForeignKey("service_principals.id"), nullable=True)

    # Scope — exactly one of these should be set (determines scope level)
    management_group_id = db.Column(db.Integer, db.ForeignKey("management_groups.id"), nullable=True)
    subscription_id     = db.Column(db.Integer, db.ForeignKey("subscriptions.id"), nullable=True)
    resource_group_id   = db.Column(db.Integer, db.ForeignKey("resource_groups.id"), nullable=True)
    resource_id         = db.Column(db.Integer, db.ForeignKey("azure_resources.id"), nullable=True)

    # Relationships
    role_definition = db.relationship("RoleDefinition", back_populates="role_assignments")
    user_principal  = db.relationship("EntraUser", back_populates="role_assignments", foreign_keys=[user_id])
    group_principal = db.relationship("EntraGroup", back_populates="role_assignments", foreign_keys=[group_id])
    sp_principal    = db.relationship("ServicePrincipal", back_populates="role_assignments", foreign_keys=[service_principal_id])

    mg_scope       = db.relationship("ManagementGroup", back_populates="role_assignments", foreign_keys=[management_group_id])
    sub_scope      = db.relationship("Subscription", back_populates="role_assignments", foreign_keys=[subscription_id])
    rg_scope       = db.relationship("ResourceGroup", back_populates="role_assignments", foreign_keys=[resource_group_id])
    resource_scope = db.relationship("AzureResource", back_populates="role_assignments", foreign_keys=[resource_id])

    @property
    def principal_type(self):
        if self.user_id: return "User"
        if self.group_id: return "Group"
        if self.service_principal_id: return "ServicePrincipal"
        return "Unknown"

    @property
    def principal_name(self):
        if self.user_principal: return self.user_principal.display_name
        if self.group_principal: return self.group_principal.display_name
        if self.sp_principal: return self.sp_principal.display_name
        return "Unknown"

    @property
    def scope_level(self):
        if self.management_group_id: return "ManagementGroup"
        if self.subscription_id: return "Subscription"
        if self.resource_group_id: return "ResourceGroup"
        if self.resource_id: return "Resource"
        return "Unknown"

    @property
    def scope_name(self):
        if self.mg_scope:       return self.mg_scope.display_name
        if self.sub_scope:      return self.sub_scope.name
        if self.rg_scope:       return self.rg_scope.name
        if self.resource_scope: return self.resource_scope.name
        return "Unknown"

    @property
    def scope_path(self):
        if self.mg_scope:       return self.mg_scope.scope_id
        if self.sub_scope:      return self.sub_scope.scope_id
        if self.rg_scope:       return self.rg_scope.scope_id
        if self.resource_scope: return f"{self.resource_scope.resource_group.scope_id}/providers/{self.resource_scope.resource_type}/{self.resource_scope.name}"
        return "Unknown"

    def __repr__(self):
        return f"<RoleAssignment {self.principal_name} → {self.role_definition.name} @ {self.scope_name}>"


# ---------------------------------------------------------------------------
# Activity Log (mirrors Azure Monitor Activity Log)
# ---------------------------------------------------------------------------

class ActivityLog(db.Model):
    """
    Azure Activity Log records all subscription-level events.
    Similar to AWS CloudTrail — answers: who did what, when, and what was the result?
    Key for security auditing, compliance, and troubleshooting.
    """
    __tablename__ = "activity_logs"

    id            = db.Column(db.Integer, primary_key=True)
    timestamp     = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    caller        = db.Column(db.String(128), nullable=False)
    operation     = db.Column(db.String(256), nullable=False)   # e.g. "Microsoft.Authorization/roleAssignments/write"
    resource_type = db.Column(db.String(128), nullable=True)
    resource_name = db.Column(db.String(128), nullable=True)
    status        = db.Column(db.String(16), default="Succeeded")   # Succeeded | Failed | Accepted
    detail        = db.Column(db.Text, nullable=True)               # JSON

    def detail_parsed(self):
        try:
            return json.loads(self.detail) if self.detail else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    def __repr__(self):
        return f"<ActivityLog {self.operation} by {self.caller}>"


# ---------------------------------------------------------------------------
# Lab Scenarios
# ---------------------------------------------------------------------------

class LabScenario(db.Model):
    """
    A guided lab scenario for AZ-104 exam preparation.
    Each lab maps to one or more AZ-104 exam domains and provides:
      - Real-world context (why you'd do this in a job)
      - Step-by-step instructions
      - Azure CLI commands you'd actually run
      - Exam tips specific to the scenario
    """
    __tablename__ = "lab_scenarios"

    id         = db.Column(db.Integer, primary_key=True)
    title      = db.Column(db.String(256), nullable=False)
    domain     = db.Column(db.String(64), nullable=False)      # "Identity & Governance", "Storage", etc.
    difficulty = db.Column(db.String(16), default="Intermediate")  # Beginner / Intermediate / Advanced
    duration   = db.Column(db.String(16), default="20 min")
    description   = db.Column(db.Text, nullable=False)
    objectives    = db.Column(db.Text, nullable=False)   # JSON array of strings
    steps         = db.Column(db.Text, nullable=False)   # JSON array of {title, instruction, cli, note}
    exam_tips     = db.Column(db.Text, nullable=True)    # JSON array of strings
    is_completed  = db.Column(db.Boolean, default=False)
    display_order = db.Column(db.Integer, default=0)

    def objectives_list(self):
        try: return json.loads(self.objectives)
        except: return []

    def steps_list(self):
        try: return json.loads(self.steps)
        except: return []

    def tips_list(self):
        try: return json.loads(self.exam_tips or "[]")
        except: return []

    def __repr__(self):
        return f"<LabScenario {self.title}>"


# ---------------------------------------------------------------------------
# Quiz Engine
# ---------------------------------------------------------------------------

class QuizQuestion(db.Model):
    """
    AZ-104 style practice exam questions.
    Each question maps to an exam domain and includes a detailed explanation
    for both correct and incorrect answers — critical for learning, not just testing.
    """
    __tablename__ = "quiz_questions"

    id             = db.Column(db.Integer, primary_key=True)
    domain         = db.Column(db.String(64), nullable=False)    # exam domain
    difficulty     = db.Column(db.String(16), default="Medium")  # Easy / Medium / Hard
    question       = db.Column(db.Text, nullable=False)
    options        = db.Column(db.Text, nullable=False)          # JSON array of 4 strings (A, B, C, D)
    correct_answer = db.Column(db.Integer, nullable=False)       # 0-based index into options
    explanation    = db.Column(db.Text, nullable=False)          # why the correct answer is right
    reference      = db.Column(db.String(256), nullable=True)    # Azure docs topic

    def options_list(self):
        try: return json.loads(self.options)
        except: return []

    def __repr__(self):
        return f"<QuizQuestion [{self.domain}] {self.question[:50]}>"
