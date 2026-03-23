# AZ-104 Azure Practice Lab

A hands-on practice application for the **Microsoft AZ-104: Azure Administrator** exam. Built with Flask, it simulates a realistic Azure environment — complete with an RBAC access simulator, guided labs, and a practice quiz engine.

## Features

### Azure RBAC Simulator
Test whether any principal can perform any action at any scope — with a full evaluation trace showing exactly which role assignment granted or denied access. Mirrors Azure's actual evaluation logic:
- Scope inheritance (Management Group → Subscription → Resource Group → Resource)
- Additive access model (union of all applicable assignments)
- Default deny when no assignment grants access
- NotActions vs Deny distinction

### Simulated "Contoso" Azure Environment
A pre-seeded realistic Azure environment to explore:
- **1 Management Group** → **2 Subscriptions** → **4 Resource Groups** → **9 Resources**
- **6 Entra ID users** with varying roles (Admin, Developer, DBA, Network Engineer, Security Analyst, Guest)
- **5 Security Groups** with group-based role assignments
- **3 Service Principals** (2 Managed Identities, 1 Application SP)
- **12 Role Assignments** demonstrating least-privilege, scope inheritance, and group-based access

### Identity Management (Entra ID)
- Create and manage users, groups, and service principals
- Toggle MFA, manage group memberships
- View effective role assignments per user (direct + inherited from groups)

### Role Definitions
- 10 built-in Azure roles (Owner, Contributor, Reader, VM Contributor, Network Contributor, Storage Blob Data Contributor, etc.)
- 1 custom role example (`Contoso-VM-Operator`) demonstrating least-privilege custom role design
- Security health checks flagging overly broad permissions

### Guided Labs (6 total)
Scenario-based exercises mapped to AZ-104 exam domains, each with step-by-step instructions, Azure CLI commands, and exam tips:

| # | Lab | Domain |
|---|-----|--------|
| 1 | Assign RBAC Roles Using Least-Privilege | Identity & Governance |
| 2 | Create a Custom Role for VM Operations | Identity & Governance |
| 3 | Audit and Remediate Over-Privileged Access | Identity & Governance |
| 4 | Configure Network Security Groups (NSGs) | Networking |
| 5 | Configure Storage Access Tiers and Security | Storage |
| 6 | Set Up Azure Monitor and Create Alerts | Monitoring & Backup |

### Practice Quiz (22 questions)
Multiple-choice questions mapped to all 5 AZ-104 exam domains, with detailed explanations for each answer. Covers common exam traps like:
- NotActions vs Deny Assignments
- NSG rule priority evaluation
- Storage tier tradeoffs
- Scope inheritance edge cases

### Azure Activity Log
Mirrors the Azure Monitor Activity Log — records all management operations with caller, operation, resource, and status.

## Getting Started

**Prerequisites:** Python 3.8+

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/az104-lab.git
cd az104-lab

# Install dependencies
pip install -r requirements.txt

# Run the app (auto-seeds the database on first run)
python app.py
```

Open **http://localhost:5001** in your browser.

The database is seeded automatically with the Contoso environment on first run.

## AZ-104 Exam Domain Coverage

| Domain | Weight | Coverage |
|--------|--------|----------|
| Manage Azure identities and governance | 20–25% | RBAC simulator, identity management, role assignments, labs 1–3 |
| Implement and manage storage | 15–20% | Storage concepts in lab 5, quiz questions |
| Deploy and manage Azure compute resources | 20–25% | VM resources in hierarchy, compute quiz questions |
| Configure and manage virtual networking | 20–25% | NSG lab, VNet resources, networking quiz |
| Monitor and maintain Azure resources | 10–15% | Activity log, monitoring lab 6, KQL examples |

## Try These in the RBAC Simulator

| Principal | Action | Scope | Expected | Why |
|-----------|--------|-------|----------|-----|
| Alice | `Microsoft.Compute/virtualMachines/write` | rg-web-prod | **ALLOW** | Owner via Management Group |
| Bob | `Microsoft.Compute/virtualMachines/write` | rg-web-prod | **ALLOW** | Contributor directly on RG |
| Bob | `Microsoft.Sql/servers/write` | rg-data-prod | **DENY** | Reader only on data RG |
| Dave | `Microsoft.Compute/virtualMachines/write` | rg-web-prod | **DENY** | Network Contributor on different RG |
| Eve | `Microsoft.Security/securityStatuses/read` | Contoso-Production | **ALLOW** | Security Reader on subscription |

## Tech Stack

- **Backend:** Python / Flask / SQLAlchemy
- **Database:** SQLite (auto-created on first run)
- **Frontend:** Bootstrap 5 + Bootstrap Icons
- **No external Azure connection required** — fully self-contained simulation

## License

MIT
