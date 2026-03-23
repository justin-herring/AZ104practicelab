"""
seed_data.py — Pre-populate the database with a realistic "Contoso" Azure environment.

Scenario: Contoso Ltd is a mid-size company with two Azure subscriptions.
This environment demonstrates real-world Azure RBAC patterns you'll encounter on the job.

Resource Hierarchy:
  Management Group: Contoso-Root
    ├── Subscription: Contoso-Production  (sub-id: aaaaaaaa-...)
    │     ├── rg-web-prod      (East US)  — VM, App Service, Load Balancer
    │     ├── rg-data-prod     (East US)  — Storage Account, SQL Server
    │     └── rg-network-prod  (East US)  — VNet, NSG, VPN Gateway
    └── Subscription: Contoso-Dev        (sub-id: bbbbbbbb-...)
          └── rg-dev           (East US)  — VMs, Storage

Identities:
  Users:   Alice (Cloud Admin), Bob (Developer), Carol (DBA), Dave (NetEng), Eve (Security)
  Groups:  CloudAdmins, Developers, DBAs, NetworkEngineers, SecurityTeam
  SPs:     webapp-prod-sp, devops-pipeline-sp, vm-managed-identity

RBAC Assignments (demonstrates scope inheritance and least-privilege):
  Alice     → Owner         @ Contoso-Root MG       (full control, inherits to everything)
  CloudAdmins group → Contributor @ Contoso-Production   (team-based access)
  Bob       → Contributor   @ rg-web-prod            (scoped to web resources)
  Bob       → Reader        @ rg-data-prod            (read-only on data — least-privilege)
  Carol     → Contributor   @ rg-data-prod            (DBA needs data access)
  Dave      → Network Contributor @ rg-network-prod   (network team)
  Eve       → Security Reader @ Contoso-Production sub (security auditor)
  webapp-prod-sp → Storage Blob Data Contributor @ rg-data-prod (app accesses storage)

Try in the RBAC Simulator:
  Alice + Microsoft.Compute/virtualMachines/start/action @ rg-web-prod → ALLOW (via MG)
  Bob   + Microsoft.Compute/virtualMachines/start/action @ rg-web-prod → ALLOW (direct)
  Bob   + Microsoft.Sql/servers/write @ rg-data-prod                   → DENY  (only Reader)
  Carol + Microsoft.Storage/storageAccounts/blobServices/read @ data   → ALLOW (Contributor)
  Dave  + Microsoft.Compute/virtualMachines/write @ rg-web-prod        → DENY  (different RG)
"""

import json
import uuid
from models import (
    db, ManagementGroup, Subscription, ResourceGroup, AzureResource,
    EntraUser, EntraGroup, ServicePrincipal,
    RoleDefinition, RoleAssignment,
    ActivityLog, LabScenario, QuizQuestion
)


# ---------------------------------------------------------------------------
# Built-in Role Definitions
# ---------------------------------------------------------------------------

BUILTIN_ROLES = [
    {
        "name": "Owner",
        "description": (
            "Grants full access to manage all resources, including the ability to assign "
            "roles in Azure RBAC. This is the most privileged built-in role — assign with care."
        ),
        "role_type": "BuiltInRole",
        "actions": ["*"],
        "not_actions": [],
        "data_actions": [],
        "not_data_actions": [],
    },
    {
        "name": "Contributor",
        "description": (
            "Grants full access to manage all resources, but does NOT allow assignment of roles "
            "or management of Azure Blueprints. Use this when you want full resource management "
            "without the ability to grant access to others."
        ),
        "role_type": "BuiltInRole",
        "actions": ["*"],
        "not_actions": [
            "Microsoft.Authorization/*/Delete",
            "Microsoft.Authorization/*/Write",
            "Microsoft.Authorization/elevateAccess/Action",
            "Microsoft.Blueprint/blueprintAssignments/write",
            "Microsoft.Blueprint/blueprintAssignments/delete",
            "Microsoft.Subscription/cancel/action",
            "Microsoft.Subscription/rename/action",
        ],
        "data_actions": [],
        "not_data_actions": [],
    },
    {
        "name": "Reader",
        "description": (
            "View all resources but cannot make any changes. "
            "Use when you want to grant visibility without modification rights. "
            "Note: Reader does NOT include read access to secrets in Key Vault or storage data."
        ),
        "role_type": "BuiltInRole",
        "actions": ["*/read"],
        "not_actions": [],
        "data_actions": [],
        "not_data_actions": [],
    },
    {
        "name": "User Access Administrator",
        "description": (
            "Manage user access to Azure resources — assign/remove role assignments. "
            "This is the ONLY built-in role (besides Owner) that can manage RBAC. "
            "Useful for delegating role assignment authority without giving full Owner access."
        ),
        "role_type": "BuiltInRole",
        "actions": [
            "*/read",
            "Microsoft.Authorization/*",
        ],
        "not_actions": [],
        "data_actions": [],
        "not_data_actions": [],
    },
    {
        "name": "Virtual Machine Contributor",
        "description": (
            "Manage VMs but not the VNet or storage account they're connected to. "
            "Good example of a service-scoped role — demonstrates least-privilege for VM ops."
        ),
        "role_type": "BuiltInRole",
        "actions": [
            "Microsoft.Authorization/*/read",
            "Microsoft.Compute/availabilitySets/*",
            "Microsoft.Compute/virtualMachines/*",
            "Microsoft.Compute/disks/write",
            "Microsoft.Compute/disks/read",
            "Microsoft.Compute/disks/delete",
            "Microsoft.Network/networkInterfaces/*",
            "Microsoft.Network/publicIPAddresses/read",
            "Microsoft.Network/virtualNetworks/read",
            "Microsoft.Storage/storageAccounts/listKeys/action",
            "Microsoft.Storage/storageAccounts/read",
        ],
        "not_actions": [],
        "data_actions": [],
        "not_data_actions": [],
    },
    {
        "name": "Network Contributor",
        "description": (
            "Manage networks but not access to them. Grants full control over "
            "VNets, NSGs, Load Balancers, VPN Gateways, etc. but not compute resources."
        ),
        "role_type": "BuiltInRole",
        "actions": [
            "Microsoft.Authorization/*/read",
            "Microsoft.Network/*",
        ],
        "not_actions": [],
        "data_actions": [],
        "not_data_actions": [],
    },
    {
        "name": "Storage Blob Data Contributor",
        "description": (
            "Read, write, and delete Azure Blob Storage containers and blobs. "
            "This is a DATA PLANE role — it uses DataActions, not Actions. "
            "Control-plane Storage Contributor does not grant blob data access!"
        ),
        "role_type": "BuiltInRole",
        "actions": [
            "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
            "Microsoft.Storage/storageAccounts/blobServices/containers/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/write",
            "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action",
        ],
        "not_actions": [],
        "data_actions": [
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action",
        ],
        "not_data_actions": [],
    },
    {
        "name": "Storage Blob Data Reader",
        "description": (
            "Read and list Azure Blob Storage containers and blobs. "
            "Data-plane read only — cannot write or delete blobs."
        ),
        "role_type": "BuiltInRole",
        "actions": [
            "Microsoft.Storage/storageAccounts/blobServices/containers/read",
            "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action",
        ],
        "not_actions": [],
        "data_actions": [
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        ],
        "not_data_actions": [],
    },
    {
        "name": "Security Reader",
        "description": (
            "View permissions for Security Center. Read-only access to security policies, "
            "security states, alerts, and recommendations. "
            "Useful for security auditors who need visibility without changes."
        ),
        "role_type": "BuiltInRole",
        "actions": [
            "Microsoft.Authorization/*/read",
            "Microsoft.Insights/alertRules/*",
            "Microsoft.Security/*",
            "Microsoft.Support/*",
        ],
        "not_actions": [],
        "data_actions": [],
        "not_data_actions": [],
    },
    {
        "name": "Monitoring Contributor",
        "description": (
            "Read all monitoring data and edit monitoring settings. "
            "Can create and manage diagnostic settings, alert rules, and action groups."
        ),
        "role_type": "BuiltInRole",
        "actions": [
            "*/read",
            "Microsoft.AlertsManagement/alerts/*",
            "Microsoft.Insights/alertRules/*",
            "Microsoft.Insights/diagnosticSettings/*",
            "Microsoft.Insights/MetricAlerts/*",
        ],
        "not_actions": [],
        "data_actions": [],
        "not_data_actions": [],
    },
    {
        "name": "Backup Contributor",
        "description": (
            "Manage backup service, but cannot create vaults or assign roles to others. "
            "Can configure backup policies and trigger backup/restore operations."
        ),
        "role_type": "BuiltInRole",
        "actions": [
            "Microsoft.Authorization/*/read",
            "Microsoft.RecoveryServices/locations/*",
            "Microsoft.RecoveryServices/Vaults/*",
            "Microsoft.Sql/servers/databases/currentSensitivityLabels/*",
        ],
        "not_actions": [],
        "data_actions": [],
        "not_data_actions": [],
    },
    # Custom role example
    {
        "name": "Contoso-VM-Operator",
        "description": (
            "Custom role: Can start/stop/restart VMs and read their status, "
            "but cannot create, delete, or modify VM configurations. "
            "Demonstrates how to create a least-privilege custom role for operations."
        ),
        "role_type": "CustomRole",
        "actions": [
            "Microsoft.Compute/virtualMachines/read",
            "Microsoft.Compute/virtualMachines/start/action",
            "Microsoft.Compute/virtualMachines/powerOff/action",
            "Microsoft.Compute/virtualMachines/restart/action",
            "Microsoft.Compute/virtualMachines/deallocate/action",
            "Microsoft.Resources/subscriptions/resourceGroups/read",
        ],
        "not_actions": [],
        "data_actions": [],
        "not_data_actions": [],
    },
]


# ---------------------------------------------------------------------------
# Lab Scenarios
# ---------------------------------------------------------------------------

LAB_SCENARIOS = [
    {
        "title": "Lab 1: Assign RBAC Roles Using Least-Privilege",
        "domain": "Identity & Governance",
        "difficulty": "Beginner",
        "duration": "15 min",
        "description": (
            "You are onboarding a new developer, Jordan, to the web team. Jordan needs to deploy "
            "and manage resources in the rg-web-prod resource group but must NOT have access to "
            "production data or the ability to assign roles to others. "
            "You will assign the Contributor role scoped to rg-web-prod."
        ),
        "objectives": json.dumps([
            "Understand the difference between Owner, Contributor, and Reader roles",
            "Assign a role scoped to a Resource Group (not a Subscription)",
            "Verify effective permissions using the RBAC Simulator",
            "Understand why scope matters for security",
        ]),
        "steps": json.dumps([
            {
                "title": "Review the built-in roles",
                "instruction": (
                    "Before assigning a role, review the Contributor role definition. "
                    "Note that Contributor has Actions: ['*'] but NotActions excludes "
                    "Microsoft.Authorization/*/Write — so a Contributor CANNOT assign roles to others."
                ),
                "cli": "az role definition list --name 'Contributor' --output json",
                "note": "Key exam tip: Contributor = full resource management, but NO RBAC management. Owner = everything.",
            },
            {
                "title": "Create the new Entra ID user",
                "instruction": (
                    "In a real scenario, you'd create the user in Entra ID first. "
                    "In this lab, use the Identity > Users section to create 'Jordan Smith'."
                ),
                "cli": "az ad user create --display-name 'Jordan Smith' --user-principal-name jordan@contoso.com --password 'TempPass123!'",
                "note": "New users have no permissions by default. Always start with no access.",
            },
            {
                "title": "Assign Contributor role at Resource Group scope",
                "instruction": (
                    "Navigate to RBAC > Role Assignments and create a new assignment. "
                    "Select: Principal=Jordan Smith, Role=Contributor, Scope=rg-web-prod. "
                    "This scopes Jordan's access to rg-web-prod ONLY — not the whole subscription."
                ),
                "cli": "az role assignment create --assignee jordan@contoso.com --role 'Contributor' --scope '/subscriptions/{sub-id}/resourceGroups/rg-web-prod'",
                "note": "Always assign at the NARROWEST scope that satisfies requirements. Subscription-wide access is rarely needed.",
            },
            {
                "title": "Verify with RBAC Simulator",
                "instruction": (
                    "Use the RBAC Simulator to verify Jordan's access. "
                    "Test: Jordan + Microsoft.Compute/virtualMachines/write @ rg-web-prod → should ALLOW. "
                    "Test: Jordan + Microsoft.Compute/virtualMachines/write @ rg-data-prod → should DENY."
                ),
                "cli": "az role assignment list --assignee jordan@contoso.com --output table",
                "note": "The simulator shows exactly WHICH role assignment granted access and at which scope.",
            },
        ]),
        "exam_tips": json.dumps([
            "Owner = full access + can assign roles. Contributor = full access, CANNOT assign roles.",
            "Scope inheritance is additive: broader scope assignments apply to all child scopes.",
            "Assigning at Resource Group scope is more secure than Subscription scope.",
            "A user with no role assignments has ZERO access — Azure defaults to deny.",
            "For the exam: know that it takes ~30 minutes for role assignments to propagate.",
        ]),
        "display_order": 1,
    },
    {
        "title": "Lab 2: Create a Custom Role for VM Operations",
        "domain": "Identity & Governance",
        "difficulty": "Intermediate",
        "duration": "25 min",
        "description": (
            "Your operations team needs to start, stop, and restart VMs but should not be able to "
            "create, delete, or modify VM configurations. No built-in role fits this requirement perfectly. "
            "You will create a custom 'VM Operator' role with exactly the permissions needed."
        ),
        "objectives": json.dumps([
            "Understand when custom roles are needed vs built-in roles",
            "Create a custom role definition with specific Actions",
            "Understand the structure of Azure RBAC role definitions",
            "Assign and test a custom role",
        ]),
        "steps": json.dumps([
            {
                "title": "Identify the required permissions",
                "instruction": (
                    "The operations team needs: start, stop, restart, and deallocate VMs, "
                    "plus read VM status. They do NOT need: create, delete, or write VMs. "
                    "First, look at the existing 'Contoso-VM-Operator' custom role in RBAC > Roles."
                ),
                "cli": "az provider operation show --namespace Microsoft.Compute | grep -i virtualMachines",
                "note": "Always start from existing built-in roles as a reference. Find the closest match and narrow it.",
            },
            {
                "title": "Review the custom role definition structure",
                "instruction": (
                    "Navigate to RBAC > Role Definitions and click 'Contoso-VM-Operator'. "
                    "Notice the Actions list only includes specific operations, not wildcards. "
                    "This is least-privilege in action."
                ),
                "cli": "az role definition list --custom-role-only true --output json",
                "note": "Custom roles must be created in JSON format. The assignableScopes field limits WHERE it can be assigned.",
            },
            {
                "title": "Create and assign the custom role",
                "instruction": (
                    "Custom roles are created with a JSON file. The key fields are: "
                    "Name, Description, Actions, NotActions, DataActions, AssignableScopes. "
                    "Once created, assign it to the operations team just like a built-in role."
                ),
                "cli": (
                    "# Create role from JSON definition file\n"
                    "az role definition create --role-definition @vm-operator-role.json\n\n"
                    "# Assign to operations group\n"
                    "az role assignment create --assignee ops-group-id --role 'Contoso-VM-Operator' "
                    "--scope '/subscriptions/{sub-id}'"
                ),
                "note": "Custom roles can be scoped to specific subscriptions via AssignableScopes.",
            },
            {
                "title": "Verify in the Simulator",
                "instruction": (
                    "Use the RBAC Simulator to test the custom role. "
                    "Verify: start/action → ALLOW, write (create/modify) → DENY. "
                    "This validates your least-privilege design."
                ),
                "cli": "az role assignment list --role 'Contoso-VM-Operator' --output table",
                "note": "Always test custom roles thoroughly before assigning to production.",
            },
        ]),
        "exam_tips": json.dumps([
            "Custom roles are defined per tenant and can be assigned in multiple subscriptions.",
            "NotActions removes permissions from Actions — it is NOT the same as an explicit Deny.",
            "Maximum 5,000 custom roles per Entra ID tenant.",
            "Custom roles require Owner or User Access Administrator to create.",
            "DataActions and NotDataActions apply to data plane (storage blobs, queue messages, etc.).",
        ]),
        "display_order": 2,
    },
    {
        "title": "Lab 3: Audit Role Assignments and Identify Over-Privileged Access",
        "domain": "Identity & Governance",
        "difficulty": "Intermediate",
        "duration": "20 min",
        "description": (
            "During a security review, you need to audit all role assignments in the Contoso-Production "
            "subscription. You need to find users with Owner or Contributor at subscription scope "
            "(should be minimized), identify Guest users with high privilege, and produce a report."
        ),
        "objectives": json.dumps([
            "List and filter role assignments across a subscription",
            "Identify over-privileged accounts (too much access, wrong scope)",
            "Understand the principle of least privilege in practice",
            "Know how to remediate: remove assignments and re-assign at narrower scope",
        ]),
        "steps": json.dumps([
            {
                "title": "List all role assignments at subscription scope",
                "instruction": (
                    "Use the RBAC > Role Assignments page to view all assignments. "
                    "Filter by scope 'Subscription' to see subscription-wide access. "
                    "Anyone with Owner or Contributor at subscription scope has very broad access."
                ),
                "cli": (
                    "az role assignment list --scope /subscriptions/{sub-id} "
                    "--include-inherited --output table"
                ),
                "note": "Subscription-scope Owner/Contributor should be rare. Most access should be at Resource Group level.",
            },
            {
                "title": "Check for Guest users with elevated access",
                "instruction": (
                    "Guest users (UserType=Guest) from partner organizations should have minimal access. "
                    "Filter the user list to find Guests, then check their role assignments. "
                    "Guests should never have Owner or Contributor at subscription level."
                ),
                "cli": (
                    "az ad user list --filter \"userType eq 'Guest'\" --output table\n"
                    "az role assignment list --assignee {guest-user-id} --output table"
                ),
                "note": "External identities (B2B guests) should be tightly scoped. Consider using PIM for time-limited access.",
            },
            {
                "title": "Review service principal assignments",
                "instruction": (
                    "Service principals (apps) often accumulate unnecessary permissions over time. "
                    "Check the webapp-prod-sp and devops-pipeline-sp service principals. "
                    "Does the pipeline SP need Contributor on the whole subscription, or just specific RGs?"
                ),
                "cli": (
                    "az role assignment list --all --query "
                    "\"[?principalType=='ServicePrincipal']\" --output table"
                ),
                "note": "Managed Identities are preferred over service principals because Azure manages credentials automatically.",
            },
            {
                "title": "Remediate: remove and re-assign at narrow scope",
                "instruction": (
                    "For each over-privileged assignment you found: "
                    "1. Remove the broad assignment. "
                    "2. Re-assign at the narrowest scope that meets requirements. "
                    "Document the change in the Activity Log."
                ),
                "cli": (
                    "# Remove over-privileged assignment\n"
                    "az role assignment delete --assignee {principal} --role 'Contributor' "
                    "--scope /subscriptions/{sub-id}\n\n"
                    "# Re-assign at resource group scope\n"
                    "az role assignment create --assignee {principal} --role 'Contributor' "
                    "--scope /subscriptions/{sub-id}/resourceGroups/{rg-name}"
                ),
                "note": "All changes are recorded in the Azure Activity Log. Use this as your audit trail.",
            },
        ]),
        "exam_tips": json.dumps([
            "Owner at subscription scope is very powerful — limit to 3 or fewer.",
            "Privileged Identity Management (PIM) enables just-in-time access — relevant for AZ-104.",
            "Use Azure AD Access Reviews to periodically audit and clean up access.",
            "Classic administrators (co-admin) are legacy and should be migrated to RBAC.",
            "The 'Security Admin' role in Defender for Cloud is separate from Azure RBAC.",
        ]),
        "display_order": 3,
    },
    {
        "title": "Lab 4: Configure Network Security Groups (NSGs)",
        "domain": "Networking",
        "difficulty": "Intermediate",
        "duration": "30 min",
        "description": (
            "Your web application VMs in rg-web-prod need to accept HTTP/HTTPS traffic from the internet "
            "but deny all other inbound traffic. Backend database servers should only accept connections "
            "from the web tier. You will configure NSG rules to implement this tiered security model."
        ),
        "objectives": json.dumps([
            "Understand NSG rule priority and evaluation order",
            "Create inbound and outbound security rules",
            "Implement a tiered network security model (web → app → data)",
            "Understand the difference between NSGs on subnets vs NICs",
        ]),
        "steps": json.dumps([
            {
                "title": "Understand NSG rule evaluation",
                "instruction": (
                    "NSG rules are evaluated by priority (100-4096). Lower number = higher priority. "
                    "Rules are evaluated in priority order — first matching rule wins. "
                    "Default rules (65000+) always allow VNet traffic and deny all internet inbound."
                ),
                "cli": "az network nsg show --name myNSG --resource-group rg-network-prod",
                "note": "Key exam trap: default rules cannot be deleted but CAN be overridden with lower priority numbers.",
            },
            {
                "title": "Allow HTTP/HTTPS from internet to web tier",
                "instruction": (
                    "Create inbound rules to allow ports 80 and 443 from 'Internet' source tag. "
                    "Azure Service Tags (Internet, VirtualNetwork, AzureLoadBalancer) are "
                    "maintained by Microsoft and simplify NSG rules."
                ),
                "cli": (
                    "# Allow HTTPS inbound (priority 100)\n"
                    "az network nsg rule create --nsg-name web-nsg --resource-group rg-network-prod "
                    "--name Allow-HTTPS-Inbound --priority 100 --direction Inbound "
                    "--source-address-prefixes Internet --destination-port-ranges 443 "
                    "--protocol Tcp --access Allow\n\n"
                    "# Allow HTTP inbound (priority 110)\n"
                    "az network nsg rule create --nsg-name web-nsg --name Allow-HTTP-Inbound "
                    "--priority 110 --direction Inbound --source-address-prefixes Internet "
                    "--destination-port-ranges 80 --protocol Tcp --access Allow "
                    "--resource-group rg-network-prod"
                ),
                "note": "HTTPS (443) gets priority 100 — lower than HTTP so HTTPS is checked first.",
            },
            {
                "title": "Restrict database tier to web tier only",
                "instruction": (
                    "The data subnet NSG should only allow SQL traffic (1433) from the web subnet. "
                    "Use subnet address prefixes as source, not IP ranges, for flexibility."
                ),
                "cli": (
                    "az network nsg rule create --nsg-name data-nsg --resource-group rg-network-prod "
                    "--name Allow-SQL-From-Web --priority 100 --direction Inbound "
                    "--source-address-prefixes 10.0.1.0/24 --destination-port-ranges 1433 "
                    "--protocol Tcp --access Allow"
                ),
                "note": "Defense-in-depth: NSG on subnet + NSG on NIC for double protection on critical resources.",
            },
            {
                "title": "Add a deny-all rule as a safety net",
                "instruction": (
                    "Add an explicit Deny All rule at priority 4000 to ensure any traffic "
                    "not explicitly allowed is blocked. This is defense-in-depth."
                ),
                "cli": (
                    "az network nsg rule create --nsg-name web-nsg --resource-group rg-network-prod "
                    "--name Deny-All-Inbound --priority 4000 --direction Inbound "
                    "--source-address-prefixes '*' --destination-port-ranges '*' "
                    "--protocol '*' --access Deny"
                ),
                "note": "While default rules already deny, an explicit Deny makes the intent clear and is easier to audit.",
            },
        ]),
        "exam_tips": json.dumps([
            "NSG rules: lower priority number = evaluated first. Priority 100 beats priority 200.",
            "Default rules: 65000 (AllowVnetInBound), 65001 (AllowAzureLoadBalancerInBound), 65500 (DenyAllInBound).",
            "Service Tags (Internet, VirtualNetwork, AzureLoadBalancer, etc.) are updated by Microsoft.",
            "NSGs can be associated with subnets AND NICs. Subnet rules apply first on inbound.",
            "Application Security Groups (ASGs) group VMs logically so you can use them in NSG rules.",
        ]),
        "display_order": 4,
    },
    {
        "title": "Lab 5: Configure Azure Storage Access Tiers and Security",
        "domain": "Storage",
        "difficulty": "Intermediate",
        "duration": "25 min",
        "description": (
            "Contoso stores financial reports in Azure Blob Storage. Reports are accessed frequently "
            "in the first 30 days, rarely for the next year, and never after that. You need to configure "
            "lifecycle management to automatically move blobs to cheaper tiers and eventually delete them."
        ),
        "objectives": json.dumps([
            "Understand the three blob access tiers: Hot, Cool, and Archive",
            "Configure lifecycle management policies",
            "Understand the cost vs access time tradeoffs",
            "Configure secure storage access (SAS tokens vs RBAC vs access keys)",
        ]),
        "steps": json.dumps([
            {
                "title": "Understand access tiers",
                "instruction": (
                    "Hot: Optimized for frequent access. Higher storage cost, lower access cost. "
                    "Cool: Infrequent access (at least 30 days). Lower storage cost, higher access cost. "
                    "Archive: Rarely accessed (at least 180 days). Lowest storage cost, but takes hours to rehydrate. "
                    "Cold: Infrequent access (at least 90 days) — newer tier between Cool and Archive."
                ),
                "cli": (
                    "# Set default access tier for new blobs\n"
                    "az storage account update --name contosodatasa --resource-group rg-data-prod "
                    "--access-tier Cool\n\n"
                    "# Change individual blob tier\n"
                    "az storage blob set-tier --account-name contosodatasa "
                    "--container-name reports --name 2023-annual.pdf --tier Archive"
                ),
                "note": "Archive tier requires rehydration (hours) before reading. Plan for this in your SLA.",
            },
            {
                "title": "Configure lifecycle management policy",
                "instruction": (
                    "Create a lifecycle policy that: moves blobs to Cool after 30 days, "
                    "moves to Archive after 365 days, and deletes after 2555 days (7 years). "
                    "This automates cost optimization without manual intervention."
                ),
                "cli": (
                    "az storage account management-policy create "
                    "--account-name contosodatasa --resource-group rg-data-prod "
                    "--policy @lifecycle-policy.json"
                ),
                "note": "Lifecycle policies run daily. There is a delay of up to 24 hours before a policy applies.",
            },
            {
                "title": "Configure secure access with SAS tokens",
                "instruction": (
                    "For external partners who need temporary access, use Shared Access Signatures (SAS). "
                    "SAS tokens grant time-limited, scope-limited access without sharing account keys. "
                    "Use User Delegation SAS (backed by Entra ID) instead of Account SAS when possible."
                ),
                "cli": (
                    "# Generate a User Delegation SAS (preferred - backed by Entra ID)\n"
                    "az storage blob generate-sas --account-name contosodatasa "
                    "--container-name reports --name 2024-q1.pdf "
                    "--permissions r --expiry 2024-12-31 "
                    "--auth-mode login --as-user\n\n"
                    "# Better: use RBAC instead of SAS for internal users\n"
                    "az role assignment create --assignee user@contoso.com "
                    "--role 'Storage Blob Data Reader' "
                    "--scope /subscriptions/{sub}/resourceGroups/rg-data-prod/..."
                ),
                "note": "RBAC is preferred over SAS for internal users. SAS is for external/temporary access.",
            },
        ]),
        "exam_tips": json.dumps([
            "Hot tier: frequent access. Cool tier: 30-day minimum. Archive: 180-day minimum, hours to rehydrate.",
            "Early deletion charges: Cool has 30-day minimum, Archive has 180-day minimum.",
            "Storage redundancy: LRS (3 copies same DC), ZRS (3 zones), GRS (2 regions), GZRS (zones + regions).",
            "Immutable storage + WORM policies are used for compliance (SEC 17a-4, FINRA).",
            "Storage Account Contributor: manages the account. Storage Blob Data Contributor: manages blob DATA.",
        ]),
        "display_order": 5,
    },
    {
        "title": "Lab 6: Set Up Azure Monitor and Create Alerts",
        "domain": "Monitoring & Backup",
        "difficulty": "Beginner",
        "duration": "20 min",
        "description": (
            "Your production web VMs need monitoring. You need to set up CPU and memory alerts, "
            "configure diagnostic settings to send logs to a Log Analytics workspace, "
            "and create an action group to notify the on-call team."
        ),
        "objectives": json.dumps([
            "Understand the difference between Azure Monitor Metrics and Logs",
            "Create metric alerts with action groups",
            "Configure diagnostic settings for resource logs",
            "Query logs with KQL in Log Analytics",
        ]),
        "steps": json.dumps([
            {
                "title": "Create a Log Analytics Workspace",
                "instruction": (
                    "Log Analytics Workspace is the central repository for log data. "
                    "Resources send diagnostic logs here, and you query them with KQL. "
                    "Create one workspace per region — avoid cross-region data transfer costs."
                ),
                "cli": (
                    "az monitor log-analytics workspace create "
                    "--resource-group rg-web-prod "
                    "--workspace-name contoso-logs "
                    "--location eastus"
                ),
                "note": "Data retention is configurable (30-730 days). Default is 30 days. Longer retention = higher cost.",
            },
            {
                "title": "Configure diagnostic settings on VMs",
                "instruction": (
                    "Diagnostic settings define WHERE to send logs and metrics. "
                    "Each resource needs its own diagnostic setting. "
                    "You can send to: Log Analytics, Storage Account, Event Hub, or Partner solutions."
                ),
                "cli": (
                    "az monitor diagnostic-settings create "
                    "--resource /subscriptions/{sub}/resourceGroups/rg-web-prod/providers/Microsoft.Compute/virtualMachines/web-vm-01 "
                    "--name 'send-to-log-analytics' "
                    "--workspace contoso-logs "
                    "--metrics '[{\"category\":\"AllMetrics\",\"enabled\":true}]' "
                    "--logs '[{\"category\":\"Administrative\",\"enabled\":true}]'"
                ),
                "note": "Guest OS metrics (CPU, memory) require the Azure Monitor Agent to be installed on the VM.",
            },
            {
                "title": "Create an action group for notifications",
                "instruction": (
                    "Action groups define WHO gets notified and HOW when an alert fires. "
                    "Notification types: Email, SMS, Push, Voice, Webhook, ITSM, Runbook, Function."
                ),
                "cli": (
                    "az monitor action-group create "
                    "--resource-group rg-web-prod "
                    "--name 'oncall-team' "
                    "--short-name 'oncall' "
                    "--action email oncall-lead oncall@contoso.com"
                ),
                "note": "Action groups can be reused across multiple alert rules. Create one per team, not per alert.",
            },
            {
                "title": "Create a CPU metric alert",
                "instruction": (
                    "Create an alert that fires when CPU > 85% for 5 minutes. "
                    "Metric alerts evaluate near-real-time (1-5 minute granularity). "
                    "Set a second alert at 95% for critical/page."
                ),
                "cli": (
                    "az monitor metrics alert create "
                    "--name 'high-cpu-alert' "
                    "--resource-group rg-web-prod "
                    "--scopes /subscriptions/{sub}/resourceGroups/rg-web-prod/providers/Microsoft.Compute/virtualMachines/web-vm-01 "
                    "--condition 'avg Percentage CPU > 85' "
                    "--window-size 5m --evaluation-frequency 1m "
                    "--action-group oncall-team "
                    "--severity 2"
                ),
                "note": "Alert severities: 0=Critical, 1=Error, 2=Warning, 3=Informational, 4=Verbose.",
            },
        ]),
        "exam_tips": json.dumps([
            "Metrics: numerical time-series data, 93 days retention. Logs: structured/unstructured, queried with KQL.",
            "Azure Monitor Agent (AMA) replaces Log Analytics Agent (MMA) and Diagnostics Extension.",
            "Log Analytics Workspace is required for log-based alerts and VM Insights.",
            "Alert processing rules can suppress alerts during maintenance windows.",
            "Azure Monitor Workbooks are interactive reports combining metrics, logs, and parameters.",
        ]),
        "display_order": 6,
    },
]


# ---------------------------------------------------------------------------
# Quiz Questions (AZ-104 mapped)
# ---------------------------------------------------------------------------

QUIZ_QUESTIONS = [
    # ── Identity & Governance ──
    {
        "domain": "Identity & Governance",
        "difficulty": "Easy",
        "question": (
            "You need to grant a developer the ability to create and manage virtual machines in a "
            "resource group, but they must NOT be able to assign roles to other users. "
            "Which built-in role should you assign?"
        ),
        "options": json.dumps([
            "Owner",
            "Contributor",
            "Virtual Machine Contributor",
            "User Access Administrator",
        ]),
        "correct_answer": 1,
        "explanation": (
            "Contributor grants full resource management but explicitly excludes "
            "Microsoft.Authorization/*/Write in its NotActions — meaning the developer "
            "cannot assign roles. Owner would give too much (includes role assignment). "
            "Virtual Machine Contributor would only allow VM operations, not creating other resources. "
            "User Access Administrator manages access, not resource creation."
        ),
        "reference": "Azure built-in roles",
    },
    {
        "domain": "Identity & Governance",
        "difficulty": "Medium",
        "question": (
            "A user is assigned the Reader role at the subscription level. "
            "A colleague then assigns them the Contributor role on a specific resource group. "
            "What is the user's effective access to resources in that resource group?"
        ),
        "options": json.dumps([
            "Reader only — the subscription-level assignment takes precedence",
            "Contributor — the more specific scope overrides",
            "Contributor — role assignments are additive, and Contributor includes all Reader actions",
            "No access — conflicting assignments cancel each other out",
        ]),
        "correct_answer": 2,
        "explanation": (
            "Azure RBAC is additive — the user has BOTH Reader (from subscription) AND Contributor "
            "(from resource group) at the resource group scope. Since Contributor includes everything "
            "Reader does plus write/delete, the effective access is Contributor. "
            "Unlike AWS IAM, there is no 'conflict resolution' — more access always wins "
            "(unless a Deny Assignment is present)."
        ),
        "reference": "Azure RBAC — how it works",
    },
    {
        "domain": "Identity & Governance",
        "difficulty": "Medium",
        "question": (
            "Your organization uses management groups. A policy is assigned at the "
            "'Contoso-Root' management group level. Which resources will this policy affect?"
        ),
        "options": json.dumps([
            "Only resources directly in the root management group",
            "All subscriptions and resources within the management group hierarchy",
            "Only the subscriptions directly under the root management group",
            "Only future subscriptions added to the management group",
        ]),
        "correct_answer": 1,
        "explanation": (
            "Management Groups use scope inheritance — assignments (policies, RBAC) at a management "
            "group level apply to ALL child management groups, subscriptions, resource groups, and resources. "
            "This makes management groups powerful for enforcing organization-wide governance. "
            "The root management group covers the entire Azure tenant."
        ),
        "reference": "Azure Management Groups",
    },
    {
        "domain": "Identity & Governance",
        "difficulty": "Hard",
        "question": (
            "A custom role has Actions: ['Microsoft.Compute/*', 'Microsoft.Storage/storageAccounts/read'] "
            "and NotActions: ['Microsoft.Compute/virtualMachines/delete']. "
            "Can a user with this role delete a virtual machine?"
        ),
        "options": json.dumps([
            "Yes — 'Microsoft.Compute/*' in Actions grants delete",
            "No — NotActions explicitly removes delete, acting as a Deny",
            "No — but another role assignment could still grant delete",
            "Yes — but only if assigned at subscription scope",
        ]),
        "correct_answer": 2,
        "explanation": (
            "This is a critical AZ-104 concept: NotActions is NOT a Deny — it removes an action "
            "from the effective permissions of THIS role. However, if the same user has ANOTHER "
            "role assignment that grants 'Microsoft.Compute/virtualMachines/delete', they CAN "
            "delete VMs. NotActions only affects the role it's defined in. "
            "True Deny requires a Deny Assignment, which is separate and overrides all role assignments."
        ),
        "reference": "Azure RBAC — Deny assignments",
    },
    {
        "domain": "Identity & Governance",
        "difficulty": "Easy",
        "question": (
            "Which Entra ID user type requires an invitation to access your Azure tenant's resources?"
        ),
        "options": json.dumps([
            "Member",
            "Guest",
            "Service Principal",
            "Managed Identity",
        ]),
        "correct_answer": 1,
        "explanation": (
            "Guest users are external identities (B2B collaboration) from outside your organization "
            "who require an invitation. They typically have limited access by default. "
            "Member users are internal organization accounts. Service Principals and Managed Identities "
            "are non-human identities for applications, not person accounts."
        ),
        "reference": "Entra ID user types",
    },
    {
        "domain": "Identity & Governance",
        "difficulty": "Medium",
        "question": (
            "You need an application running on an Azure VM to access Azure Key Vault secrets "
            "without storing any credentials in the application code. What should you use?"
        ),
        "options": json.dumps([
            "A service principal with a client secret stored in app settings",
            "A system-assigned managed identity on the VM",
            "A user account with the Key Vault Secrets User role",
            "Storage account access keys",
        ]),
        "correct_answer": 1,
        "explanation": (
            "System-assigned Managed Identity is the correct answer. Azure automatically creates and "
            "manages the credentials — no secrets to store, rotate, or leak. The VM gets an identity "
            "that can be assigned RBAC roles. Assign 'Key Vault Secrets User' to the managed identity. "
            "Service principals with client secrets require credential management. "
            "User accounts shouldn't be used for app authentication."
        ),
        "reference": "Azure Managed Identities",
    },
    {
        "domain": "Identity & Governance",
        "difficulty": "Hard",
        "question": (
            "You assign Alice the 'Contributor' role at the subscription level. "
            "You then create a Deny Assignment at the resource group level blocking 'Microsoft.Compute/*'. "
            "What can Alice do with virtual machines in that resource group?"
        ),
        "options": json.dumps([
            "Full VM management — Contributor at subscription overrides resource group deny",
            "No VM operations — Deny Assignments override all role assignments",
            "Read-only VM access — deny blocks write but not read",
            "Full VM management — Deny Assignments don't affect built-in roles",
        ]),
        "correct_answer": 1,
        "explanation": (
            "Deny Assignments override ALL role assignments, including those from broader scopes. "
            "Even though Alice has Contributor at subscription scope, the Deny Assignment at "
            "resource group scope blocks all Microsoft.Compute/* operations in that RG. "
            "Deny Assignments are used by Azure Blueprints and some managed applications. "
            "They cannot be created directly by users — only through Blueprints or ARM templates."
        ),
        "reference": "Azure RBAC Deny Assignments",
    },
    # ── Storage ──
    {
        "domain": "Storage",
        "difficulty": "Easy",
        "question": (
            "You are storing log files that are accessed frequently in the first week, "
            "then rarely accessed for the next 6 months, after which they can be deleted. "
            "Which storage tier strategy minimizes cost?"
        ),
        "options": json.dumps([
            "Store all logs in Archive tier immediately",
            "Hot for first week, then move to Cool, delete after 6 months",
            "Store all logs in Hot tier permanently",
            "Cool for first week, then move to Archive",
        ]),
        "correct_answer": 1,
        "explanation": (
            "Hot tier is cost-effective for frequent access (first week). "
            "Cool tier is optimized for data accessed less than once per 30 days — good for months 1-6. "
            "Archive tier is for rarely-accessed data that can tolerate hours of retrieval latency. "
            "Since logs are accessed in the first week, Archive immediately would be too slow. "
            "Use Azure Blob Lifecycle Management to automate these tier transitions."
        ),
        "reference": "Azure Blob Storage access tiers",
    },
    {
        "domain": "Storage",
        "difficulty": "Medium",
        "question": (
            "Your compliance team requires that financial documents stored in Azure Blob Storage "
            "cannot be modified or deleted for 7 years after creation. What should you configure?"
        ),
        "options": json.dumps([
            "Set the blob access tier to Archive",
            "Configure a time-based retention policy with WORM (Write Once, Read Many)",
            "Assign the Storage Blob Data Reader role to all users",
            "Enable soft delete with a 7-year retention period",
        ]),
        "correct_answer": 1,
        "explanation": (
            "WORM (Write Once, Read Many) immutable storage policies prevent blobs from being "
            "modified or deleted for a specified retention period. This meets compliance requirements "
            "like SEC 17a-4, CFTC, and FINRA. Archive tier just changes cost/access speed, it doesn't "
            "prevent deletion. Soft delete helps recover accidentally deleted blobs but doesn't prevent "
            "intentional deletion. Reader role just controls who can read, not protection from modification."
        ),
        "reference": "Azure Immutable Blob Storage",
    },
    {
        "domain": "Storage",
        "difficulty": "Medium",
        "question": (
            "You need to give a third-party vendor temporary, read-only access to specific blobs "
            "in your storage account for 24 hours. The vendor does not have an Azure account. "
            "What is the best approach?"
        ),
        "options": json.dumps([
            "Share the storage account access key",
            "Create a guest Entra ID user and assign Storage Blob Data Reader",
            "Generate a Shared Access Signature (SAS) with read permission and 24-hour expiry",
            "Make the blob container public",
        ]),
        "correct_answer": 2,
        "explanation": (
            "A SAS token grants time-limited, scope-limited access without requiring an Azure account. "
            "Set permissions=read, expiry=24 hours, and scope to specific containers or blobs. "
            "Sharing the account key gives full access and doesn't expire — never do this. "
            "Creating a guest user is complex for temporary access and doesn't auto-expire. "
            "Making the container public removes all access control — dangerous for sensitive data."
        ),
        "reference": "Azure Storage SAS tokens",
    },
    {
        "domain": "Storage",
        "difficulty": "Hard",
        "question": (
            "A storage account has zone-redundant storage (ZRS) replication. "
            "What happens if an entire Azure availability zone fails?"
        ),
        "options": json.dumps([
            "Data is lost — ZRS only protects against disk failures",
            "Data is unavailable until the zone recovers",
            "Data remains accessible — ZRS replicates synchronously across 3 availability zones",
            "Automatic failover to a secondary region occurs",
        ]),
        "correct_answer": 2,
        "explanation": (
            "ZRS (Zone-Redundant Storage) replicates data synchronously across 3 availability zones "
            "in the same region. If one zone fails, data remains accessible from the other two zones. "
            "ZRS protects against zone failures but NOT against regional failures. "
            "For regional resilience, use GRS (Geo-Redundant Storage) or GZRS. "
            "LRS (Locally Redundant) = 3 copies in same datacenter. "
            "GRS = LRS + async replication to paired region."
        ),
        "reference": "Azure Storage redundancy",
    },
    # ── Compute ──
    {
        "domain": "Compute",
        "difficulty": "Easy",
        "question": (
            "You need to deploy 5 identical VMs for a stateless web tier, with automatic scaling "
            "based on CPU utilization, and VMs should be replaced if they become unhealthy. "
            "What should you use?"
        ),
        "options": json.dumps([
            "Availability Set with 5 VMs",
            "Virtual Machine Scale Set (VMSS)",
            "Azure App Service Plan",
            "5 individual VMs with an Availability Zone per VM",
        ]),
        "correct_answer": 1,
        "explanation": (
            "Virtual Machine Scale Sets (VMSS) support auto-scaling based on metrics (CPU, memory, etc.), "
            "automatic VM replacement when health probes fail, and identical VM configurations. "
            "Availability Sets provide fault and update domain distribution but not auto-scaling. "
            "Azure App Service is for web apps (PaaS), not IaaS VMs. "
            "Individual VMs with zones provides zone resilience but not auto-scaling."
        ),
        "reference": "Azure Virtual Machine Scale Sets",
    },
    {
        "domain": "Compute",
        "difficulty": "Medium",
        "question": (
            "You have a VM that needs maintenance. You want to minimize downtime "
            "and ensure the VM is protected against both hardware failures AND planned maintenance. "
            "What should you configure?"
        ),
        "options": json.dumps([
            "Deploy the VM in an Availability Set",
            "Deploy the VM in an Availability Zone",
            "Deploy VMs across multiple Availability Zones with a Load Balancer",
            "Create a VM backup policy",
        ]),
        "correct_answer": 2,
        "explanation": (
            "Availability Zones protect against datacenter (zone) failures and provide the highest "
            "SLA (99.99%). Deploying across multiple zones with a load balancer ensures that even if "
            "one zone has planned maintenance, traffic routes to healthy zones. "
            "Availability Sets protect within a single datacenter (fault/update domains) — SLA 99.95%. "
            "A single VM in a zone gets 99.9% SLA. VM backup is for disaster recovery, not HA."
        ),
        "reference": "Azure VM availability options",
    },
    {
        "domain": "Compute",
        "difficulty": "Medium",
        "question": (
            "Your development team needs a cost-effective way to run containerized microservices "
            "without managing the underlying infrastructure. The workloads run for a few hours daily "
            "and don't require persistent storage. What Azure service should you recommend?"
        ),
        "options": json.dumps([
            "Azure Kubernetes Service (AKS)",
            "Azure Container Instances (ACI)",
            "Azure App Service with containers",
            "Azure Virtual Machines with Docker",
        ]),
        "correct_answer": 1,
        "explanation": (
            "Azure Container Instances (ACI) is the simplest way to run containers without managing "
            "servers or Kubernetes clusters. You pay per second only when running — cost-effective "
            "for intermittent workloads. AKS is for complex, production-grade container orchestration "
            "with persistent management overhead. App Service with containers is better for "
            "always-on web apps. VMs with Docker have significant management overhead."
        ),
        "reference": "Azure Container Instances",
    },
    # ── Networking ──
    {
        "domain": "Networking",
        "difficulty": "Easy",
        "question": (
            "Two VNets in the same region need to communicate privately. VMs in VNet-A should "
            "reach VMs in VNet-B using private IP addresses. What should you configure?"
        ),
        "options": json.dumps([
            "VNet-to-VNet VPN Gateway connection",
            "VNet Peering",
            "Azure ExpressRoute",
            "Azure Private Link",
        ]),
        "correct_answer": 1,
        "explanation": (
            "VNet Peering connects VNets using the Azure backbone network — no internet traffic, "
            "low latency, high bandwidth. For same-region VNets, use regional VNet peering. "
            "VPN Gateway works but adds latency, complexity, and cost — overkill for same-region. "
            "ExpressRoute is for on-premises to Azure connections. "
            "Private Link exposes Azure services (not VNets) via private endpoints."
        ),
        "reference": "Azure VNet Peering",
    },
    {
        "domain": "Networking",
        "difficulty": "Medium",
        "question": (
            "Your on-premises network needs a reliable, high-bandwidth, private connection to Azure "
            "for a financial application that cannot use the public internet. What should you use?"
        ),
        "options": json.dumps([
            "Site-to-Site VPN Gateway",
            "Azure ExpressRoute",
            "Azure VNet Peering",
            "Point-to-Site VPN",
        ]),
        "correct_answer": 1,
        "explanation": (
            "Azure ExpressRoute provides a private, dedicated connection from on-premises to Azure "
            "through a connectivity provider — it does NOT go over the public internet. "
            "It offers guaranteed bandwidth (50 Mbps to 100 Gbps), lower latency, and higher SLAs. "
            "Site-to-Site VPN is cheaper but uses the internet (encrypted) — not suitable for "
            "financial apps requiring no internet path. Point-to-Site VPN is for individual clients."
        ),
        "reference": "Azure ExpressRoute",
    },
    {
        "domain": "Networking",
        "difficulty": "Hard",
        "question": (
            "An NSG has these inbound rules: Priority 100: Allow port 443 from Internet. "
            "Priority 200: Deny port 443 from Internet. "
            "Priority 65500: DenyAllInBound (default). "
            "What happens to HTTPS traffic from the internet?"
        ),
        "options": json.dumps([
            "Denied — the deny at 200 overrides the allow at 100",
            "Allowed — priority 100 is evaluated first and matches; evaluation stops",
            "Denied — the default DenyAllInBound rule always wins",
            "Allowed — Allow rules always take precedence over Deny rules",
        ]),
        "correct_answer": 1,
        "explanation": (
            "NSG rules are evaluated in priority order (lowest number first). Priority 100 (Allow 443) "
            "is evaluated BEFORE priority 200 (Deny 443). Since the Allow rule matches first, "
            "the traffic is allowed and evaluation stops — the Deny rule at 200 is never reached. "
            "This is different from AWS security groups where all rules are evaluated. "
            "In NSGs: first matching rule wins. Order (priority) matters critically."
        ),
        "reference": "Azure NSG rule evaluation",
    },
    {
        "domain": "Networking",
        "difficulty": "Medium",
        "question": (
            "You need to load balance HTTP/HTTPS traffic to your web VMs and use URL-based routing "
            "to send /api/* requests to one backend pool and /images/* to another. "
            "Which Azure service should you use?"
        ),
        "options": json.dumps([
            "Azure Load Balancer (Standard)",
            "Azure Application Gateway",
            "Azure Traffic Manager",
            "Azure Front Door",
        ]),
        "correct_answer": 1,
        "explanation": (
            "Azure Application Gateway is a Layer 7 (HTTP/HTTPS) load balancer that supports "
            "URL-based routing, path-based routing, SSL termination, WAF, and cookie-based sessions. "
            "Azure Load Balancer is Layer 4 (TCP/UDP) — no URL routing capability. "
            "Azure Traffic Manager is DNS-based global load balancing (not URL path routing). "
            "Azure Front Door is global CDN + load balancing but more complex and expensive "
            "for simple path-based routing within a region."
        ),
        "reference": "Azure Application Gateway",
    },
    # ── Monitoring & Backup ──
    {
        "domain": "Monitoring & Backup",
        "difficulty": "Easy",
        "question": (
            "You need to retain Azure VM activity logs for 2 years for compliance. "
            "The default Azure Monitor retention period is 90 days. What should you configure?"
        ),
        "options": json.dumps([
            "Create a diagnostic setting to export logs to a Log Analytics Workspace with 2-year retention",
            "Increase the Azure Monitor retention setting to 2 years",
            "Export logs to a storage account using a diagnostic setting",
            "Both A and C are valid solutions",
        ]),
        "correct_answer": 3,
        "explanation": (
            "You can export Activity Logs to either a Log Analytics Workspace (with retention up to 730 days) "
            "or to a Storage Account (where you control retention with lifecycle policies for up to 2+ years). "
            "For long-term compliance archival (2+ years), a Storage Account is more cost-effective. "
            "Log Analytics workspace maximum retention is 730 days (2 years) with an additional "
            "archive period available. Both options work for 2-year retention."
        ),
        "reference": "Azure Monitor Activity Log retention",
    },
    {
        "domain": "Monitoring & Backup",
        "difficulty": "Medium",
        "question": (
            "A VM backup fails with an error. You need to investigate what happened, "
            "including who initiated the backup, when, and the error details. Where do you look?"
        ),
        "options": json.dumps([
            "Azure Monitor Metrics",
            "Azure Activity Log",
            "VM diagnostic logs in the guest OS",
            "Azure Security Center alerts",
        ]),
        "correct_answer": 1,
        "explanation": (
            "The Azure Activity Log records all subscription-level management operations — "
            "who did what, when, and whether it succeeded or failed. It's the equivalent of "
            "AWS CloudTrail. For backup operations (Microsoft.RecoveryServices), the Activity Log "
            "shows the caller, timestamp, operation type, and status. "
            "Azure Monitor Metrics show numeric time-series data, not operation logs. "
            "VM guest OS logs are for OS-level events, not Azure management operations."
        ),
        "reference": "Azure Activity Log",
    },
    {
        "domain": "Monitoring & Backup",
        "difficulty": "Medium",
        "question": (
            "You need to write a query to find all failed login attempts to Azure VMs "
            "in the last 24 hours. The VM logs are being sent to a Log Analytics Workspace. "
            "What query language do you use?"
        ),
        "options": json.dumps([
            "SQL (Structured Query Language)",
            "PowerShell",
            "KQL (Kusto Query Language)",
            "Azure CLI queries with --query flag",
        ]),
        "correct_answer": 2,
        "explanation": (
            "KQL (Kusto Query Language) is used to query data in Azure Log Analytics, "
            "Azure Monitor, Application Insights, and Microsoft Sentinel. "
            "Example: SecurityEvent | where EventID == 4625 | where TimeGenerated > ago(24h) "
            "| summarize count() by Account. "
            "KQL is a read-only language optimized for time-series data analysis. "
            "SQL is not used for Log Analytics. PowerShell can call the API but not query directly."
        ),
        "reference": "KQL overview",
    },
    {
        "domain": "Monitoring & Backup",
        "difficulty": "Hard",
        "question": (
            "Your RTO (Recovery Time Objective) is 4 hours and RPO (Recovery Point Objective) is 1 hour. "
            "Your Azure VMs use Azure Backup with daily backups at midnight. "
            "A failure occurs at 3 PM. What is the maximum data loss?"
        ),
        "options": json.dumps([
            "0 hours — Azure Backup uses continuous protection",
            "15 hours — from midnight to 3 PM",
            "24 hours — the backup frequency",
            "1 hour — matching the RPO",
        ]),
        "correct_answer": 1,
        "explanation": (
            "With daily backups at midnight, the last backup before a 3 PM failure was at midnight — "
            "15 hours ago. This means up to 15 hours of data could be lost, which VIOLATES the 1-hour RPO. "
            "To meet a 1-hour RPO, you'd need hourly backups or continuous data protection. "
            "RPO defines the maximum acceptable data loss (time between last backup and failure). "
            "RTO defines the maximum acceptable downtime (time to restore). "
            "These are key concepts for both AZ-104 and real-world disaster recovery planning."
        ),
        "reference": "Azure Backup RPO and RTO",
    },
]


# ---------------------------------------------------------------------------
# Seed function
# ---------------------------------------------------------------------------

def seed(app):
    """Create all seed data inside the given Flask app context."""
    with app.app_context():
        if EntraUser.query.count() > 0:
            print("Database already seeded — skipping.")
            return

        print("Seeding Contoso Azure environment...")

        # ── Role Definitions ──
        role_map = {}
        for r in BUILTIN_ROLES:
            role = RoleDefinition(
                name=r["name"],
                description=r["description"],
                role_type=r["role_type"],
                actions=json.dumps(r["actions"]),
                not_actions=json.dumps(r["not_actions"]),
                data_actions=json.dumps(r["data_actions"]),
                not_data_actions=json.dumps(r["not_data_actions"]),
            )
            db.session.add(role)
            role_map[r["name"]] = role

        db.session.flush()

        # ── Resource Hierarchy ──
        root_mg = ManagementGroup(name="contoso-root", display_name="Contoso Root")
        db.session.add(root_mg)
        db.session.flush()

        prod_sub = Subscription(
            name="Contoso-Production",
            subscription_id="aaaaaaaa-1111-2222-3333-444444444444",
            management_group_id=root_mg.id,
        )
        dev_sub = Subscription(
            name="Contoso-Dev",
            subscription_id="bbbbbbbb-5555-6666-7777-888888888888",
            management_group_id=root_mg.id,
        )
        db.session.add_all([prod_sub, dev_sub])
        db.session.flush()

        rg_web   = ResourceGroup(name="rg-web-prod",     subscription_id=prod_sub.id, location="eastus",   tags='{"env":"prod","team":"web"}')
        rg_data  = ResourceGroup(name="rg-data-prod",    subscription_id=prod_sub.id, location="eastus",   tags='{"env":"prod","team":"data"}')
        rg_net   = ResourceGroup(name="rg-network-prod", subscription_id=prod_sub.id, location="eastus",   tags='{"env":"prod","team":"network"}')
        rg_dev   = ResourceGroup(name="rg-dev",          subscription_id=dev_sub.id,  location="eastus2",  tags='{"env":"dev","team":"engineering"}')
        db.session.add_all([rg_web, rg_data, rg_net, rg_dev])
        db.session.flush()

        # Resources in rg-web-prod
        vm_web01  = AzureResource(name="web-vm-01",      resource_type="Microsoft.Compute/virtualMachines",  resource_group_id=rg_web.id,  location="eastus",  properties='{"size":"Standard_D2s_v3","os":"Windows Server 2022"}')
        vm_web02  = AzureResource(name="web-vm-02",      resource_type="Microsoft.Compute/virtualMachines",  resource_group_id=rg_web.id,  location="eastus",  properties='{"size":"Standard_D2s_v3","os":"Windows Server 2022"}')
        app_svc   = AzureResource(name="contoso-webapp", resource_type="Microsoft.Web/sites",                resource_group_id=rg_web.id,  location="eastus",  properties='{"kind":"app","sku":"P1v3"}')
        # Resources in rg-data-prod
        storage   = AzureResource(name="contosodatasa",   resource_type="Microsoft.Storage/storageAccounts", resource_group_id=rg_data.id, location="eastus",  properties='{"sku":"Standard_GRS","kind":"StorageV2"}')
        sql_srv   = AzureResource(name="contoso-sql-srv", resource_type="Microsoft.Sql/servers",             resource_group_id=rg_data.id, location="eastus",  properties='{"version":"12.0"}')
        keyvault  = AzureResource(name="contoso-kv",      resource_type="Microsoft.KeyVault/vaults",         resource_group_id=rg_data.id, location="eastus",  properties='{"sku":"standard"}')
        # Resources in rg-network-prod
        vnet      = AzureResource(name="vnet-prod",       resource_type="Microsoft.Network/virtualNetworks", resource_group_id=rg_net.id,  location="eastus",  properties='{"addressSpace":"10.0.0.0/16"}')
        nsg_web   = AzureResource(name="nsg-web",         resource_type="Microsoft.Network/networkSecurityGroups", resource_group_id=rg_net.id, location="eastus", properties='{"rules":2}')
        # Resource in rg-dev
        vm_dev    = AzureResource(name="dev-vm-01",       resource_type="Microsoft.Compute/virtualMachines",  resource_group_id=rg_dev.id,  location="eastus2", properties='{"size":"Standard_B2s","os":"Ubuntu 22.04"}')

        db.session.add_all([vm_web01, vm_web02, app_svc, storage, sql_srv, keyvault, vnet, nsg_web, vm_dev])
        db.session.flush()

        # ── Entra ID Users ──
        alice = EntraUser(display_name="Alice Chen",    upn="alice@contoso.com",   job_title="Cloud Administrator",  department="IT",       mfa_enabled=True)
        bob   = EntraUser(display_name="Bob Martinez",  upn="bob@contoso.com",     job_title="Senior Developer",     department="Eng",      mfa_enabled=True)
        carol = EntraUser(display_name="Carol Davis",   upn="carol@contoso.com",   job_title="Database Administrator", department="Data",   mfa_enabled=True)
        dave  = EntraUser(display_name="Dave Wilson",   upn="dave@contoso.com",    job_title="Network Engineer",     department="NetOps",   mfa_enabled=True)
        eve   = EntraUser(display_name="Eve Thompson",  upn="eve@contoso.com",     job_title="Security Analyst",     department="Security", mfa_enabled=True)
        frank = EntraUser(display_name="Frank Guest",   upn="frank@partner.com",   job_title="External Consultant",  user_type="Guest",     mfa_enabled=False)
        db.session.add_all([alice, bob, carol, dave, eve, frank])
        db.session.flush()

        # ── Entra ID Groups ──
        g_admins  = EntraGroup(display_name="CloudAdmins",       group_type="Security",    description="Azure cloud administrators",       assignable_to_role=True)
        g_devs    = EntraGroup(display_name="Developers",        group_type="Security",    description="Engineering developers",            assignable_to_role=True)
        g_dbas    = EntraGroup(display_name="DBAs",              group_type="Security",    description="Database administrators",           assignable_to_role=True)
        g_net     = EntraGroup(display_name="NetworkEngineers",  group_type="Security",    description="Network operations team",           assignable_to_role=True)
        g_sec     = EntraGroup(display_name="SecurityTeam",      group_type="Security",    description="Security and compliance team",      assignable_to_role=True)
        db.session.add_all([g_admins, g_devs, g_dbas, g_net, g_sec])
        db.session.flush()

        g_admins.members.append(alice)
        g_devs.members.extend([bob, frank])
        g_dbas.members.append(carol)
        g_net.members.append(dave)
        g_sec.members.append(eve)
        db.session.flush()

        # ── Service Principals ──
        webapp_sp  = ServicePrincipal(display_name="webapp-prod-sp",     sp_type="ManagedIdentity", app_id=str(uuid.uuid4()), description="Managed identity for Contoso Web App — accesses Key Vault and Storage")
        pipeline_sp = ServicePrincipal(display_name="devops-pipeline-sp", sp_type="Application",    app_id=str(uuid.uuid4()), description="DevOps pipeline service principal for CI/CD deployments")
        vm_mi       = ServicePrincipal(display_name="web-vm-01-identity",  sp_type="ManagedIdentity", app_id=str(uuid.uuid4()), description="System-assigned managed identity for web-vm-01")
        db.session.add_all([webapp_sp, pipeline_sp, vm_mi])
        db.session.flush()

        # ── Role Assignments (demonstrates scope inheritance) ──
        assignments = [
            # Alice: Owner at Root MG → inherits to everything
            RoleAssignment(role_definition=role_map["Owner"], user_id=alice.id, management_group_id=root_mg.id,
                           description="Cloud Admin — full access via management group scope"),
            # CloudAdmins group: Contributor on Production subscription
            RoleAssignment(role_definition=role_map["Contributor"], group_id=g_admins.id, subscription_id=prod_sub.id,
                           description="Cloud admin team access to production subscription"),
            # Bob: Contributor on rg-web-prod (least-privilege: scoped to web resources)
            RoleAssignment(role_definition=role_map["Contributor"], user_id=bob.id, resource_group_id=rg_web.id,
                           description="Developer access to web resource group"),
            # Bob: Reader on rg-data-prod (can view data, cannot modify)
            RoleAssignment(role_definition=role_map["Reader"], user_id=bob.id, resource_group_id=rg_data.id,
                           description="Read-only access to data resources — least-privilege"),
            # Carol: Contributor on rg-data-prod (DBA needs full data access)
            RoleAssignment(role_definition=role_map["Contributor"], user_id=carol.id, resource_group_id=rg_data.id,
                           description="DBA access to data resource group"),
            # Dave: Network Contributor on rg-network-prod
            RoleAssignment(role_definition=role_map["Network Contributor"], user_id=dave.id, resource_group_id=rg_net.id,
                           description="Network engineer access to network resource group"),
            # Eve: Security Reader on Production subscription (cross-RG visibility for security)
            RoleAssignment(role_definition=role_map["Security Reader"], user_id=eve.id, subscription_id=prod_sub.id,
                           description="Security team read-only access across production"),
            # Developers group: Reader on Production (see what's running, can't change it)
            RoleAssignment(role_definition=role_map["Reader"], group_id=g_devs.id, subscription_id=prod_sub.id,
                           description="Developers can view production resources"),
            # webapp-prod-sp: Storage Blob Data Contributor on rg-data-prod
            RoleAssignment(role_definition=role_map["Storage Blob Data Contributor"], service_principal_id=webapp_sp.id,
                           resource_group_id=rg_data.id,
                           description="Web app managed identity reads/writes blob storage"),
            # pipeline-sp: Contributor on rg-web-prod + rg-dev (deploys to these environments)
            RoleAssignment(role_definition=role_map["Contributor"], service_principal_id=pipeline_sp.id,
                           resource_group_id=rg_web.id,
                           description="CI/CD pipeline deploys to web resource group"),
            RoleAssignment(role_definition=role_map["Contributor"], service_principal_id=pipeline_sp.id,
                           resource_group_id=rg_dev.id,
                           description="CI/CD pipeline deploys to dev resource group"),
            # vm-mi: Storage Blob Data Reader on the storage account (least-privilege: one resource)
            RoleAssignment(role_definition=role_map["Storage Blob Data Reader"], service_principal_id=vm_mi.id,
                           resource_id=storage.id,
                           description="VM managed identity reads blobs from storage — resource-level scope"),
        ]
        db.session.add_all(assignments)
        db.session.flush()

        # ── Activity Log ──
        logs = [
            ActivityLog(caller="system", operation="Microsoft.Authorization/roleAssignments/write",
                        resource_type="Microsoft.Authorization/roleAssignments", resource_name="Owner@contoso-root",
                        status="Succeeded"),
            ActivityLog(caller="alice@contoso.com", operation="Microsoft.Compute/virtualMachines/write",
                        resource_type="Microsoft.Compute/virtualMachines", resource_name="web-vm-01",
                        status="Succeeded"),
            ActivityLog(caller="devops-pipeline-sp", operation="Microsoft.Web/sites/write",
                        resource_type="Microsoft.Web/sites", resource_name="contoso-webapp",
                        status="Succeeded"),
            ActivityLog(caller="bob@contoso.com", operation="Microsoft.Compute/virtualMachines/read",
                        resource_type="Microsoft.Compute/virtualMachines", resource_name="web-vm-01",
                        status="Succeeded"),
            ActivityLog(caller="bob@contoso.com", operation="Microsoft.Sql/servers/write",
                        resource_type="Microsoft.Sql/servers", resource_name="contoso-sql-srv",
                        status="Failed", detail='{"error":"Authorization failed — insufficient permissions"}'),
            ActivityLog(caller="alice@contoso.com", operation="Microsoft.Authorization/roleAssignments/write",
                        resource_type="Microsoft.Authorization/roleAssignments", resource_name="Reader@rg-data-prod",
                        status="Succeeded"),
            ActivityLog(caller="eve@contoso.com", operation="Microsoft.Security/securityStatuses/read",
                        resource_type="Microsoft.Security", resource_name="Contoso-Production",
                        status="Succeeded"),
        ]
        db.session.add_all(logs)

        # ── Labs ──
        for lab_data in LAB_SCENARIOS:
            lab = LabScenario(**lab_data)
            db.session.add(lab)

        # ── Quiz Questions ──
        for q_data in QUIZ_QUESTIONS:
            q = QuizQuestion(**q_data)
            db.session.add(q)

        db.session.commit()

        print("Seeding complete! Contoso Azure environment ready.")
        print("\nTry in the RBAC Simulator:")
        print("  Alice  + Microsoft.Compute/virtualMachines/write @ rg-web-prod -> ALLOW (Owner via MG)")
        print("  Bob    + Microsoft.Compute/virtualMachines/write @ rg-web-prod -> ALLOW (Contributor on RG)")
        print("  Bob    + Microsoft.Sql/servers/write @ rg-data-prod            -> DENY  (Reader only)")
        print("  Dave   + Microsoft.Compute/virtualMachines/write @ rg-web-prod -> DENY  (wrong RG scope)")
        print("  Eve    + Microsoft.Security/* @ prod-sub                       -> ALLOW (Security Reader)")
