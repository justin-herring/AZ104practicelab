"""
app.py — Flask application for the AZ-104 Azure Practice Lab.

Routes:
  GET  /                             → dashboard
  GET  /identity/users               → Entra ID user list
  GET  /identity/users/<id>          → user detail + effective role assignments
  POST /identity/users/create        → create user
  POST /identity/users/<id>/delete   → delete user
  GET  /identity/groups              → group list
  GET  /identity/groups/<id>         → group detail
  POST /identity/groups/create       → create group
  POST /identity/groups/<id>/delete  → delete group
  POST /identity/groups/<id>/add-member    → add user to group
  POST /identity/groups/<id>/remove-member → remove user from group
  GET  /identity/service-principals  → service principal list

  GET  /rbac/assignments             → all role assignments
  POST /rbac/assignments/create      → create role assignment
  POST /rbac/assignments/<id>/delete → delete role assignment
  GET  /rbac/roles                   → role definitions
  GET  /rbac/roles/<id>              → role definition detail

  GET  /rbac/simulator               → RBAC access simulator UI
  POST /rbac/simulator/evaluate      → evaluate access (JSON API)

  GET  /resources                    → resource hierarchy
  GET  /activity-log                 → activity log
  GET  /labs                         → lab scenario list
  GET  /labs/<id>                    → lab detail
  POST /labs/<id>/complete           → mark lab complete/incomplete

  GET  /quiz                         → quiz domain selection
  GET  /quiz/start                   → start a quiz session
  POST /quiz/answer                  → submit answer (JSON API)
  GET  /quiz/results                 → quiz results
"""

import json
import os
from datetime import datetime, timezone

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session

from models import (
    db, ManagementGroup, Subscription, ResourceGroup, AzureResource,
    EntraUser, EntraGroup, ServicePrincipal,
    RoleDefinition, RoleAssignment,
    ActivityLog, LabScenario, QuizQuestion
)
from rbac_engine import evaluate_access, check_role_health
import seed_data as seed_module

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = "az104-lab-dev-key"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'az104.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log_activity(caller: str, operation: str, resource_type: str = None,
                 resource_name: str = None, status: str = "Succeeded", detail: dict = None):
    entry = ActivityLog(
        caller=caller,
        operation=operation,
        resource_type=resource_type,
        resource_name=resource_name,
        status=status,
        detail=json.dumps(detail) if detail else None,
    )
    db.session.add(entry)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    users    = EntraUser.query.all()
    groups   = EntraGroup.query.all()
    sps      = ServicePrincipal.query.all()
    roles    = RoleDefinition.query.all()
    assignments = RoleAssignment.query.all()
    rgs      = ResourceGroup.query.all()
    resources = AzureResource.query.all()
    recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(8).all()
    labs     = LabScenario.query.order_by(LabScenario.display_order).all()
    completed_labs = sum(1 for l in labs if l.is_completed)

    # Security observations
    warnings = []
    no_mfa = [u for u in users if not u.mfa_enabled and u.user_type == "Member"]
    if no_mfa:
        warnings.append(f"{len(no_mfa)} Member user(s) do not have MFA enabled: {', '.join(u.display_name for u in no_mfa)}")

    guests = [u for u in users if u.user_type == "Guest"]
    for guest in guests:
        for ra in guest.role_assignments:
            if ra.role_definition.name in ("Owner", "Contributor"):
                warnings.append(f"Guest user '{guest.display_name}' has {ra.role_definition.name} role at {ra.scope_name} — review recommended.")

    owner_sub = [ra for ra in assignments if ra.role_definition.name == "Owner" and ra.scope_level == "Subscription"]
    if len(owner_sub) > 2:
        warnings.append(f"{len(owner_sub)} Owner assignments at Subscription scope — consider reducing (best practice: ≤3).")

    custom_roles = RoleDefinition.query.filter_by(role_type="CustomRole").all()
    for role in custom_roles:
        issues = check_role_health(role)
        for issue in issues:
            warnings.append(f"Custom role '{role.name}': {issue}")

    return render_template(
        "dashboard.html",
        users=users, groups=groups, sps=sps, roles=roles,
        assignments=assignments, rgs=rgs, resources=resources,
        recent_logs=recent_logs, warnings=warnings,
        labs=labs, completed_labs=completed_labs,
    )


# ---------------------------------------------------------------------------
# Identity — Users
# ---------------------------------------------------------------------------

@app.route("/identity/users")
def users_list():
    users = EntraUser.query.order_by(EntraUser.display_name).all()
    return render_template("identity/users.html", users=users)


@app.route("/identity/users/<int:user_id>")
def user_detail(user_id):
    user = EntraUser.query.get_or_404(user_id)
    all_groups = EntraGroup.query.order_by(EntraGroup.display_name).all()
    all_assignments = user.all_role_assignments()
    return render_template(
        "identity/user_detail.html",
        user=user,
        all_groups=all_groups,
        all_assignments=all_assignments,
    )


@app.route("/identity/users/create", methods=["POST"])
def user_create():
    display_name = request.form.get("display_name", "").strip()
    upn          = request.form.get("upn", "").strip()
    department   = request.form.get("department", "").strip()
    job_title    = request.form.get("job_title", "").strip()
    user_type    = request.form.get("user_type", "Member")

    if not display_name or not upn:
        flash("Display name and UPN are required.", "danger")
        return redirect(url_for("users_list"))
    if EntraUser.query.filter_by(upn=upn).first():
        flash(f"User '{upn}' already exists.", "danger")
        return redirect(url_for("users_list"))

    user = EntraUser(
        display_name=display_name, upn=upn,
        department=department, job_title=job_title, user_type=user_type
    )
    db.session.add(user)
    log_activity("admin", "Microsoft.Directory/users/create",
                 "Microsoft.Directory/users", display_name)
    db.session.commit()
    flash(f"User '{display_name}' created.", "success")
    return redirect(url_for("user_detail", user_id=user.id))


@app.route("/identity/users/<int:user_id>/delete", methods=["POST"])
def user_delete(user_id):
    user = EntraUser.query.get_or_404(user_id)
    name = user.display_name
    db.session.delete(user)
    log_activity("admin", "Microsoft.Directory/users/delete",
                 "Microsoft.Directory/users", name)
    db.session.commit()
    flash(f"User '{name}' deleted.", "warning")
    return redirect(url_for("users_list"))


@app.route("/identity/users/<int:user_id>/toggle-mfa", methods=["POST"])
def user_toggle_mfa(user_id):
    user = EntraUser.query.get_or_404(user_id)
    user.mfa_enabled = not user.mfa_enabled
    status = "enabled" if user.mfa_enabled else "disabled"
    log_activity("admin", f"Microsoft.Directory/users/authentication/update",
                 "Microsoft.Directory/users", user.display_name,
                 detail={"mfa": status})
    db.session.commit()
    flash(f"MFA {status} for {user.display_name}.", "success")
    return redirect(url_for("user_detail", user_id=user_id))


# ---------------------------------------------------------------------------
# Identity — Groups
# ---------------------------------------------------------------------------

@app.route("/identity/groups")
def groups_list():
    groups = EntraGroup.query.order_by(EntraGroup.display_name).all()
    return render_template("identity/groups.html", groups=groups)


@app.route("/identity/groups/<int:group_id>")
def group_detail(group_id):
    group    = EntraGroup.query.get_or_404(group_id)
    all_users = EntraUser.query.order_by(EntraUser.display_name).all()
    return render_template("identity/group_detail.html", group=group, all_users=all_users)


@app.route("/identity/groups/create", methods=["POST"])
def group_create():
    display_name = request.form.get("display_name", "").strip()
    group_type   = request.form.get("group_type", "Security")
    description  = request.form.get("description", "").strip()
    if not display_name:
        flash("Group name is required.", "danger")
        return redirect(url_for("groups_list"))
    group = EntraGroup(display_name=display_name, group_type=group_type, description=description)
    db.session.add(group)
    log_activity("admin", "Microsoft.Directory/groups/create",
                 "Microsoft.Directory/groups", display_name)
    db.session.commit()
    flash(f"Group '{display_name}' created.", "success")
    return redirect(url_for("group_detail", group_id=group.id))


@app.route("/identity/groups/<int:group_id>/delete", methods=["POST"])
def group_delete(group_id):
    group = EntraGroup.query.get_or_404(group_id)
    name  = group.display_name
    db.session.delete(group)
    log_activity("admin", "Microsoft.Directory/groups/delete",
                 "Microsoft.Directory/groups", name)
    db.session.commit()
    flash(f"Group '{name}' deleted.", "warning")
    return redirect(url_for("groups_list"))


@app.route("/identity/groups/<int:group_id>/add-member", methods=["POST"])
def group_add_member(group_id):
    group   = EntraGroup.query.get_or_404(group_id)
    user_id = request.form.get("user_id", type=int)
    user    = EntraUser.query.get_or_404(user_id)
    if user not in group.members:
        group.members.append(user)
        log_activity("admin", "Microsoft.Directory/groups/members/add",
                     "Microsoft.Directory/groups", group.display_name,
                     detail={"member": user.upn})
        db.session.commit()
        flash(f"'{user.display_name}' added to '{group.display_name}'.", "success")
    else:
        flash(f"'{user.display_name}' is already in this group.", "info")
    return redirect(url_for("group_detail", group_id=group_id))


@app.route("/identity/groups/<int:group_id>/remove-member", methods=["POST"])
def group_remove_member(group_id):
    group   = EntraGroup.query.get_or_404(group_id)
    user_id = request.form.get("user_id", type=int)
    user    = EntraUser.query.get_or_404(user_id)
    if user in group.members:
        group.members.remove(user)
        log_activity("admin", "Microsoft.Directory/groups/members/remove",
                     "Microsoft.Directory/groups", group.display_name,
                     detail={"member": user.upn})
        db.session.commit()
        flash(f"'{user.display_name}' removed from '{group.display_name}'.", "warning")
    return redirect(url_for("group_detail", group_id=group_id))


# ---------------------------------------------------------------------------
# Identity — Service Principals
# ---------------------------------------------------------------------------

@app.route("/identity/service-principals")
def service_principals_list():
    sps = ServicePrincipal.query.order_by(ServicePrincipal.display_name).all()
    return render_template("identity/service_principals.html", sps=sps)


# ---------------------------------------------------------------------------
# RBAC — Role Assignments
# ---------------------------------------------------------------------------

@app.route("/rbac/assignments")
def rbac_assignments():
    assignments = RoleAssignment.query.order_by(RoleAssignment.assigned_at.desc()).all()
    users  = EntraUser.query.order_by(EntraUser.display_name).all()
    groups = EntraGroup.query.order_by(EntraGroup.display_name).all()
    sps    = ServicePrincipal.query.order_by(ServicePrincipal.display_name).all()
    roles  = RoleDefinition.query.order_by(RoleDefinition.name).all()
    mgs    = ManagementGroup.query.all()
    subs   = Subscription.query.all()
    rgs    = ResourceGroup.query.all()
    resources = AzureResource.query.order_by(AzureResource.name).all()
    return render_template(
        "rbac/role_assignments.html",
        assignments=assignments, users=users, groups=groups, sps=sps,
        roles=roles, mgs=mgs, subs=subs, rgs=rgs, resources=resources,
    )


@app.route("/rbac/assignments/create", methods=["POST"])
def rbac_assignment_create():
    role_id        = request.form.get("role_id", type=int)
    principal_type = request.form.get("principal_type")
    principal_id   = request.form.get("principal_id", type=int)
    scope_type     = request.form.get("scope_type")
    scope_id       = request.form.get("scope_id", type=int)
    description    = request.form.get("description", "").strip()

    if not all([role_id, principal_type, principal_id, scope_type, scope_id]):
        flash("All fields are required.", "danger")
        return redirect(url_for("rbac_assignments"))

    role = RoleDefinition.query.get_or_404(role_id)

    ra = RoleAssignment(role_definition_id=role_id, description=description)

    if principal_type == "user":
        ra.user_id = principal_id
        principal_name = EntraUser.query.get(principal_id).display_name if EntraUser.query.get(principal_id) else "Unknown"
    elif principal_type == "group":
        ra.group_id = principal_id
        principal_name = EntraGroup.query.get(principal_id).display_name if EntraGroup.query.get(principal_id) else "Unknown"
    elif principal_type == "sp":
        ra.service_principal_id = principal_id
        principal_name = ServicePrincipal.query.get(principal_id).display_name if ServicePrincipal.query.get(principal_id) else "Unknown"
    else:
        flash("Invalid principal type.", "danger")
        return redirect(url_for("rbac_assignments"))

    scope_map = {
        "mg":       ("management_group_id",  "ManagementGroup"),
        "sub":      ("subscription_id",       "Subscription"),
        "rg":       ("resource_group_id",     "ResourceGroup"),
        "resource": ("resource_id",           "Resource"),
    }
    if scope_type not in scope_map:
        flash("Invalid scope type.", "danger")
        return redirect(url_for("rbac_assignments"))

    attr, scope_label = scope_map[scope_type]
    setattr(ra, attr, scope_id)

    db.session.add(ra)
    log_activity("admin", "Microsoft.Authorization/roleAssignments/write",
                 "Microsoft.Authorization/roleAssignments",
                 f"{role.name}@{scope_label}",
                 detail={"principal": principal_name, "role": role.name})
    db.session.commit()
    flash(f"Role assignment created: {principal_name} → {role.name}.", "success")
    return redirect(url_for("rbac_assignments"))


@app.route("/rbac/assignments/<int:assignment_id>/delete", methods=["POST"])
def rbac_assignment_delete(assignment_id):
    ra = RoleAssignment.query.get_or_404(assignment_id)
    detail = f"{ra.principal_name} → {ra.role_definition.name} @ {ra.scope_name}"
    log_activity("admin", "Microsoft.Authorization/roleAssignments/delete",
                 "Microsoft.Authorization/roleAssignments", detail)
    db.session.delete(ra)
    db.session.commit()
    flash(f"Role assignment deleted: {detail}.", "warning")
    return redirect(url_for("rbac_assignments"))


# ---------------------------------------------------------------------------
# RBAC — Role Definitions
# ---------------------------------------------------------------------------

@app.route("/rbac/roles")
def rbac_roles():
    roles = RoleDefinition.query.order_by(RoleDefinition.role_type, RoleDefinition.name).all()
    return render_template("rbac/role_definitions.html", roles=roles)


@app.route("/rbac/roles/<int:role_id>")
def rbac_role_detail(role_id):
    role    = RoleDefinition.query.get_or_404(role_id)
    health  = check_role_health(role)
    return render_template("rbac/role_detail.html", role=role, health=health)


# ---------------------------------------------------------------------------
# RBAC — Access Simulator
# ---------------------------------------------------------------------------

@app.route("/rbac/simulator")
def rbac_simulator():
    users  = EntraUser.query.order_by(EntraUser.display_name).all()
    groups = EntraGroup.query.order_by(EntraGroup.display_name).all()
    sps    = ServicePrincipal.query.order_by(ServicePrincipal.display_name).all()
    mgs    = ManagementGroup.query.all()
    subs   = Subscription.query.all()
    rgs    = ResourceGroup.query.order_by(ResourceGroup.name).all()
    resources = AzureResource.query.order_by(AzureResource.name).all()

    # Common actions for the dropdown
    sample_actions = [
        ("Microsoft.Compute/virtualMachines/read", "Read VM"),
        ("Microsoft.Compute/virtualMachines/write", "Create/Update VM"),
        ("Microsoft.Compute/virtualMachines/delete", "Delete VM"),
        ("Microsoft.Compute/virtualMachines/start/action", "Start VM"),
        ("Microsoft.Compute/virtualMachines/powerOff/action", "Stop VM"),
        ("Microsoft.Storage/storageAccounts/read", "Read Storage Account"),
        ("Microsoft.Storage/storageAccounts/write", "Create/Update Storage Account"),
        ("Microsoft.Network/virtualNetworks/read", "Read VNet"),
        ("Microsoft.Network/virtualNetworks/write", "Create/Update VNet"),
        ("Microsoft.Network/networkSecurityGroups/write", "Create/Update NSG"),
        ("Microsoft.Authorization/roleAssignments/write", "Assign Roles"),
        ("Microsoft.Authorization/roleAssignments/delete", "Remove Role Assignments"),
        ("Microsoft.Security/securityStatuses/read", "Read Security Status"),
        ("Microsoft.Sql/servers/write", "Create/Update SQL Server"),
        ("Microsoft.Web/sites/write", "Create/Update App Service"),
        ("Microsoft.Resources/subscriptions/resourceGroups/write", "Create Resource Group"),
    ]

    return render_template(
        "rbac/simulator.html",
        users=users, groups=groups, sps=sps,
        mgs=mgs, subs=subs, rgs=rgs, resources=resources,
        sample_actions=sample_actions,
    )


@app.route("/rbac/simulator/evaluate", methods=["POST"])
def rbac_simulator_evaluate():
    data           = request.get_json()
    principal_type = data.get("principal_type", "user")
    principal_id   = data.get("principal_id")
    action         = data.get("action", "").strip()
    scope_type     = data.get("scope_type", "rg")
    scope_id       = data.get("scope_id")

    if not action:
        return jsonify({"error": "action is required"}), 400

    # Resolve principal
    if principal_type == "user":
        principal = EntraUser.query.get(principal_id)
        if not principal:
            return jsonify({"error": "User not found"}), 404
    elif principal_type == "group":
        principal = EntraGroup.query.get(principal_id)
        if not principal:
            return jsonify({"error": "Group not found"}), 404
    elif principal_type == "sp":
        principal = ServicePrincipal.query.get(principal_id)
        if not principal:
            return jsonify({"error": "Service Principal not found"}), 404
    else:
        return jsonify({"error": "Invalid principal_type"}), 400

    # Resolve target scope
    target_scope = {}
    if scope_type == "mg":
        target_scope["management_group"] = ManagementGroup.query.get(scope_id)
    elif scope_type == "sub":
        sub = Subscription.query.get(scope_id)
        target_scope["subscription"] = sub
        if sub and sub.management_group:
            target_scope["management_group"] = sub.management_group
    elif scope_type == "rg":
        rg = ResourceGroup.query.get(scope_id)
        target_scope["resource_group"] = rg
        if rg:
            target_scope["subscription"] = rg.subscription
            if rg.subscription and rg.subscription.management_group:
                target_scope["management_group"] = rg.subscription.management_group
    elif scope_type == "resource":
        resource = AzureResource.query.get(scope_id)
        target_scope["resource"] = resource
        if resource and resource.resource_group:
            rg = resource.resource_group
            target_scope["resource_group"] = rg
            target_scope["subscription"] = rg.subscription
            if rg.subscription and rg.subscription.management_group:
                target_scope["management_group"] = rg.subscription.management_group

    result = evaluate_access(principal, action, target_scope)

    # Log the simulation
    log_activity(
        caller="simulator",
        operation="Microsoft.Authorization/checkAccess/action",
        resource_type="RBAC Simulator",
        resource_name=f"{principal.display_name} → {action}",
        status=result.decision,
        detail={"principal": principal.display_name, "action": action, "decision": result.decision},
    )
    db.session.commit()

    steps_out = [
        {
            "assignment_id": s.assignment_id,
            "role_name":     s.role_name,
            "scope_level":   s.scope_level,
            "scope_name":    s.scope_name,
            "outcome":       s.outcome,
            "reason":        s.reason,
        }
        for s in result.steps
    ]

    return jsonify({
        "decision":       result.decision,
        "reason":         result.reason,
        "matching_role":  result.matching_role,
        "matching_scope": result.matching_scope,
        "principal":      principal.display_name,
        "action":         action,
        "steps":          steps_out,
    })


# ---------------------------------------------------------------------------
# Resources — Hierarchy View
# ---------------------------------------------------------------------------

@app.route("/resources")
def resources_hierarchy():
    mgs   = ManagementGroup.query.all()
    subs  = Subscription.query.all()
    rgs   = ResourceGroup.query.order_by(ResourceGroup.name).all()
    resources = AzureResource.query.order_by(AzureResource.name).all()
    return render_template(
        "resources/hierarchy.html",
        mgs=mgs, subs=subs, rgs=rgs, resources=resources,
    )


# ---------------------------------------------------------------------------
# Activity Log
# ---------------------------------------------------------------------------

@app.route("/activity-log")
def activity_log():
    page     = request.args.get("page", 1, type=int)
    per_page = 20
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template("activity_log.html", logs=logs)


# ---------------------------------------------------------------------------
# Labs
# ---------------------------------------------------------------------------

@app.route("/labs")
def labs_list():
    labs = LabScenario.query.order_by(LabScenario.display_order).all()
    domains = sorted(set(l.domain for l in labs))
    return render_template("labs/lab_list.html", labs=labs, domains=domains)


@app.route("/labs/<int:lab_id>")
def lab_detail(lab_id):
    lab = LabScenario.query.get_or_404(lab_id)
    all_labs = LabScenario.query.order_by(LabScenario.display_order).all()
    lab_index = next((i for i, l in enumerate(all_labs) if l.id == lab_id), 0)
    prev_lab = all_labs[lab_index - 1] if lab_index > 0 else None
    next_lab = all_labs[lab_index + 1] if lab_index < len(all_labs) - 1 else None
    return render_template("labs/lab_detail.html", lab=lab, prev_lab=prev_lab, next_lab=next_lab)


@app.route("/labs/<int:lab_id>/complete", methods=["POST"])
def lab_toggle_complete(lab_id):
    lab = LabScenario.query.get_or_404(lab_id)
    lab.is_completed = not lab.is_completed
    db.session.commit()
    status = "completed" if lab.is_completed else "marked incomplete"
    flash(f"Lab '{lab.title}' {status}.", "success" if lab.is_completed else "info")
    return redirect(url_for("lab_detail", lab_id=lab_id))


# ---------------------------------------------------------------------------
# Quiz
# ---------------------------------------------------------------------------

@app.route("/quiz")
def quiz_home():
    domains = db.session.query(QuizQuestion.domain).distinct().order_by(QuizQuestion.domain).all()
    domains = [d[0] for d in domains]
    counts  = {d: QuizQuestion.query.filter_by(domain=d).count() for d in domains}
    total   = QuizQuestion.query.count()
    return render_template("quiz/quiz_home.html", domains=domains, counts=counts, total=total)


@app.route("/quiz/start")
def quiz_start():
    domain = request.args.get("domain", "all")
    count  = request.args.get("count", 10, type=int)
    count  = max(5, min(count, 20))

    if domain == "all":
        questions = QuizQuestion.query.order_by(db.func.random()).limit(count).all()
    else:
        questions = QuizQuestion.query.filter_by(domain=domain).order_by(db.func.random()).limit(count).all()

    if not questions:
        flash("No questions available for that domain.", "warning")
        return redirect(url_for("quiz_home"))

    session["quiz_questions"] = [q.id for q in questions]
    session["quiz_answers"]   = {}
    session["quiz_domain"]    = domain
    session["quiz_current"]   = 0

    return redirect(url_for("quiz_question"))


@app.route("/quiz/question")
def quiz_question():
    q_ids = session.get("quiz_questions", [])
    current = session.get("quiz_current", 0)

    if not q_ids or current >= len(q_ids):
        return redirect(url_for("quiz_results"))

    question = QuizQuestion.query.get(q_ids[current])
    if not question:
        return redirect(url_for("quiz_results"))

    answers = session.get("quiz_answers", {})

    return render_template(
        "quiz/quiz_question.html",
        question=question,
        current=current + 1,
        total=len(q_ids),
        answered=str(question.id) in answers,
        selected_answer=answers.get(str(question.id)),
    )


@app.route("/quiz/answer", methods=["POST"])
def quiz_answer():
    data      = request.get_json()
    q_id      = data.get("question_id")
    answer    = data.get("answer")

    question = QuizQuestion.query.get(q_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    is_correct = (answer == question.correct_answer)

    answers = session.get("quiz_answers", {})
    answers[str(q_id)] = answer
    session["quiz_answers"] = answers

    return jsonify({
        "correct":      is_correct,
        "correct_index": question.correct_answer,
        "explanation":  question.explanation,
        "reference":    question.reference or "",
    })


@app.route("/quiz/next", methods=["POST"])
def quiz_next():
    current = session.get("quiz_current", 0)
    session["quiz_current"] = current + 1
    return redirect(url_for("quiz_question"))


@app.route("/quiz/results")
def quiz_results():
    q_ids   = session.get("quiz_questions", [])
    answers = session.get("quiz_answers", {})

    if not q_ids:
        return redirect(url_for("quiz_home"))

    questions = QuizQuestion.query.filter(QuizQuestion.id.in_(q_ids)).all()
    q_map = {q.id: q for q in questions}

    results = []
    correct_count = 0
    for q_id in q_ids:
        q = q_map.get(q_id)
        if not q:
            continue
        user_answer = answers.get(str(q_id))
        is_correct  = user_answer == q.correct_answer
        if is_correct:
            correct_count += 1
        results.append({
            "question": q,
            "user_answer": user_answer,
            "is_correct": is_correct,
            "options": q.options_list(),
        })

    score = round((correct_count / len(results)) * 100) if results else 0
    pass_fail = "PASS" if score >= 70 else "NEEDS WORK"

    return render_template(
        "quiz/quiz_results.html",
        results=results,
        correct_count=correct_count,
        total=len(results),
        score=score,
        pass_fail=pass_fail,
    )


# ---------------------------------------------------------------------------
# Database initialization (runs on import — works with gunicorn and direct)
# ---------------------------------------------------------------------------

with app.app_context():
    db.create_all()
    seed_module.seed(app)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5001)
