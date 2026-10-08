"""Semantic consistency review of the final report and upstream State."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

NEGATIONS = (
    "不",
    "不能",
    "无法",
    "未",
    "没有",
    "尚未",
    "尚无",
    "不足以",
    "不得",
    "不等同于",
    "不代表",
    "不确认",
    "未证明",
)
NEUTRAL_CONTEXTS = (
    "确认或排除",
    "核验是否",
    "核对是否",
    "判断是否",
    "需要核验",
    "待核验",
    "若",
    "如",
    "一旦",
)
CONSTRAINT_CONTEXTS = (
    "不得",
    "不能",
    "不可",
    "禁止",
    "不应",
    "必须核验",
    "需要核验",
    "必须有",
    "需要有",
    "需有",
    "无法确认",
    "尚未确认",
    "未确认",
    "未证实",
    "未观察",
    "未发现",
    "没有证据",
    "无证据",
    "无直接证据",
    "不足以证明",
    "不足以确认",
    "不支持",
    "不代表",
    "不等同",
    "并非",
    "假设",
    "推断",
    "待核验",
    "待确认",
    "需核验",
    "核销",
    "避免",
    "示例",
    "作为",
    "用作",
    "当作",
)

SUCCESS_CLAIM_PATTERNS = (
    r"攻击(?:已经|已)?成功(?!\s*(?:性|与否|的|证据|条件|标准))",
    r"成功利用(?!\s*(?:性|与否|的|条件|标准))",
    r"(?:数据|敏感数据|密码|凭据)(?:已经|已)?外泄(?!\s*(?:性|与否|的|证据|条件|标准))",
    r"未授权访问(?:已经|已)?成功(?!\s*(?:性|与否|的|条件|标准))",
)


@dataclass(frozen=True)
class ReviewRule:
    """Executable review-rule metadata shared by State and report reviews."""

    rule_id: str
    category: str
    severity: str
    rollback_target: str
    auto_fixable: bool
    revision_action: str


REVIEW_RULE_REGISTRY: dict[str, ReviewRule] = {
    # Structured State Review rules.
    "http_state_is_structured": ReviewRule(
        "RULE_HTTP_STATE_SCHEMA", "NORMALIZATION_ERROR", "BLOCKING", "normalization", False,
        "重新执行告警规范化并重新建立 HTTP/业务状态。",
    ),
    "business_context_is_structured": ReviewRule(
        "RULE_BUSINESS_CONTEXT_SCHEMA", "BUSINESS_CONTEXT_ERROR", "BLOCKING", "business_context", False,
        "重新执行 Business Context Classifier。",
    ),
    "scene_matches_business_context": ReviewRule(
        "RULE_SCENE_BUSINESS_ALIGNMENT", "SECURITY_CLASSIFICATION_ERROR", "MAJOR", "scene_classification", False,
        "重新执行 Security Problem Classifier，重新选择与业务动作一致的场景。",
    ),
    "router_matches_security_problem": ReviewRule(
        "RULE_ROUTER_SECURITY_ALIGNMENT", "ROUTER_ERROR", "BLOCKING", "workflow_router", False,
        "重新执行 Workflow Router，不让报告文本覆盖路由状态。",
    ),
    "workflow_is_registered": ReviewRule(
        "RULE_WORKFLOW_REGISTERED", "ROUTER_ERROR", "BLOCKING", "workflow_router", False,
        "重新计算已注册 Workflow、risk profile 和工具计划。",
    ),
    "workflow_is_eligible": ReviewRule(
        "RULE_WORKFLOW_ELIGIBILITY", "WORKFLOW_ELIGIBILITY_ERROR", "BLOCKING", "workflow_router", False,
        "重新执行 Workflow Eligibility；证据不足时回退 generic_workflow。",
    ),
    "main_scene_uses_current_evidence": ReviewRule(
        "RULE_WORKFLOW_EVIDENCE_ALIGNMENT", "EVIDENCE_MAPPING_ERROR", "BLOCKING", "workflow_evidence", False,
        "重新构建 Workflow Evidence，禁止嵌入/历史证据支持当前主场景。",
    ),
    "workflow_contract_is_bound": ReviewRule(
        "RULE_WORKFLOW_CONTRACT", "EVIDENCE_MAPPING_ERROR", "BLOCKING", "workflow_evidence", False,
        "重新绑定 Router 选择与 Workflow 证据契约。",
    ),
    "risk_profile_matches_scene": ReviewRule(
        "RULE_SCENE_RISK_PROFILE_ALIGNMENT", "RISK_PROFILE_ERROR", "BLOCKING", "risk", False,
        "按最新 Router 选择重新计算 Risk Profile。",
    ),
    "risk_profile_matches_router": ReviewRule(
        "RULE_ROUTER_RISK_PROFILE_ALIGNMENT", "RISK_PROFILE_ERROR", "BLOCKING", "risk", False,
        "丢弃旧 Risk Profile，按 Router 的 profile_id 重新计算。",
    ),
    "upstream_state_is_consistent": ReviewRule(
        "RULE_UPSTREAM_STATE_CONSISTENCY", "NORMALIZATION_ERROR", "BLOCKING", "normalization", False,
        "重新执行规范化及其下游结构化节点，不能只重写报告。",
    ),
    # Final report rules.  These are deliberately separate from State rules.
    "http_status_matches_report": ReviewRule(
        "RULE_HTTP_200_NOT_EXECUTION", "REPORT_FACT_ERROR", "MAJOR", "report", True,
        "根据当前 HTTP 状态修正报告事实表述。",
    ),
    "business_result_matches_report": ReviewRule(
        "RULE_BUSINESS_RESULT_ALIGNMENT", "REPORT_FACT_ERROR", "MAJOR", "report", True,
        "根据结构化 business_result 修正报告，不把未知写成已知或相反。",
    ),
    "authorization_matches_report": ReviewRule(
        "RULE_AUTH_OBSERVATION_ALIGNMENT", "REPORT_FACT_ERROR", "MAJOR", "report", True,
        "保留认证字段存在性与有效性未确认的边界。",
    ),
    "field_applicability_is_respected": ReviewRule(
        "RULE_FIELD_APPLICABILITY", "REPORT_FACT_ERROR", "MAJOR", "report", True,
        "删除将不适用字段解释为攻击事实或反证的表述。",
    ),
    "remediation_matches_scene": ReviewRule(
        "RULE_REMEDIATION_SCENE_ALIGNMENT", "REPORT_WORDING_ERROR", "MAJOR", "report", True,
        "按选定场景重写处置与修复建议。",
    ),
    "security_claims_have_evidence": ReviewRule(
        "RULE_SECURITY_CLAIM_EVIDENCE", "REPORT_FACT_ERROR", "BLOCKING", "report", True,
        "删除无直接证据的攻击成功/未授权成功结论，并列为待确认。",
    ),
    "report_state_version_matches": ReviewRule(
        "RULE_REPORT_STATE_VERSION", "REPORT_FACT_ERROR", "BLOCKING", "report", True,
        "使用当前 State Version 重新生成报告。",
    ),
    "required_report_sections": ReviewRule(
        "RULE_REPORT_STRUCTURE", "REPORT_STRUCTURE_ERROR", "MAJOR", "report", True,
        "补齐语义章节标题，避免仅通过短语或模板文字伪造完整报告。",
    ),
    "report_knowledge_references": ReviewRule(
        "RULE_KNOWLEDGE_REFERENCE", "KNOWLEDGE_MISMATCH", "MAJOR", "report", True,
        "只引用本次检索返回的知识片段，重新生成报告引用。",
    ),
    "report_evidence_references": ReviewRule(
        "RULE_EVIDENCE_REFERENCE", "REPORT_FACT_ERROR", "BLOCKING", "report", True,
        "删除不存在的 Evidence ID 并改用当前 Evidence Store。",
    ),
    "report_minimum_structure": ReviewRule(
        "RULE_REPORT_MINIMUM_STRUCTURE", "REPORT_STRUCTURE_ERROR", "MAJOR", "report", True,
        "重新生成完整报告结构，而不是返回截断内容。",
    ),
    "llm_report_review": ReviewRule(
        "RULE_INDEPENDENT_REPORT_REVIEW", "REPORT_WORDING_ERROR", "MAJOR", "report", True,
        "将独立复核反馈逐项传给下一轮报告生成。",
    ),
    "llm_analysis_review": ReviewRule(
        "RULE_INDEPENDENT_ANALYSIS_REVIEW", "ANALYSIS_FACT_ERROR", "BLOCKING", "risk", True,
        "将独立复核反馈传回 Risk/证据推理层，重新建立 confirmed_facts、hypotheses 和结论边界。",
    ),
    "review_repair_loop": ReviewRule(
        "RULE_REVIEW_REPAIR_LOOP", "UNKNOWN_ERROR", "BLOCKING", "report", False,
        "停止重复重试，保留状态版本、哈希和复核证据，转人工检查。",
    ),
}

ROLLBACK_PRIORITY = (
    "normalization",
    "business_context",
    "security_classification",
    "scene_classification",
    "workflow_router",
    "workflow_evidence",
    "risk",
    "knowledge",
    "report",
)

ANALYSIS_ROLLBACK_TARGETS = frozenset(
    {
        "normalization",
        "business_context",
        "security_classification",
        "scene_classification",
        "workflow_router",
        "workflow_evidence",
        "risk",
    }
)

SECTION_ALIASES: dict[str, tuple[str, ...]] = {
    "执行摘要": ("执行摘要", "摘要", "事件摘要"),
    "事件管理": ("事件管理", "事件处置", "事件概览"),
    "场景识别": ("场景识别", "安全场景", "攻击场景识别"),
    "事实范围": ("事实范围", "事实边界", "当前事件范围"),
    "确认事实": ("确认事实", "已确认事实", "已证实事实", "观察到的事实"),
    "尚未确认": ("尚未确认", "待确认事项", "未确认事项", "待验证事项", "待验证假设"),
    "事件成立层级": ("事件成立层级", "事件判断层级", "成立层级"),
    "核心证据链": ("核心证据链", "证据链", "关键证据"),
    "业务与技术影响": ("业务与技术影响", "影响分析", "业务影响与技术影响"),
    "攻击场景": ("攻击场景", "攻击路径", "场景分析"),
    "风险维度": ("风险维度", "风险分析", "风险评估"),
    "研判置信度": ("研判置信度", "置信度", "置信度说明"),
    "证据覆盖": ("证据覆盖", "证据覆盖率", "证据完整性"),
    "安全实体": ("安全实体", "实体", "相关实体"),
    "IOC 语义": ("IOC 语义", "IOC语义", "IOC 分析", "IOC分析", "威胁指标语义"),
    "关联排查": ("关联排查", "关联分析", "扩展排查"),
    "研判结论": ("研判结论", "分析结论", "安全结论"),
    "响应": ("响应", "响应建议", "处置建议"),
    "恢复": ("恢复", "恢复建议", "恢复计划"),
    "关闭标准": ("关闭标准", "结案标准", "关闭条件"),
    "沟通": ("沟通", "沟通建议", "通知与沟通"),
    "升级": ("升级", "升级建议", "升级路径"),
    "能力改进路线图": ("能力改进路线图", "改进路线图", "能力改进"),
    "知识库依据": ("知识库依据", "知识依据", "知识库参考"),
}


def review_rule_registry() -> list[dict[str, Any]]:
    """Return safe metadata for diagnostics and the UI; no executable code."""
    return [
        {
            "check": check,
            "rule_id": rule.rule_id,
            "category": rule.category,
            "severity": rule.severity,
            "rollback_target": rule.rollback_target,
            "auto_fixable": rule.auto_fixable,
            "revision_action": rule.revision_action,
        }
        for check, rule in REVIEW_RULE_REGISTRY.items()
    ]


def _rule(check: str, fallback_target: str = "report") -> ReviewRule:
    rule = REVIEW_RULE_REGISTRY.get(check)
    if rule:
        return rule
    return ReviewRule(
        check.upper(), "UNKNOWN_ERROR", "MAJOR", fallback_target, False,
        "需要人工检查该复核规则的上游状态。",
    )


def _failure(check: str, message: str, fallback_target: str = "report") -> dict[str, Any]:
    rule = _rule(check, fallback_target)
    return {
        "check": check,
        "rule_id": rule.rule_id,
        "severity": rule.severity,
        "error_category": rule.category,
        "failure_type": rule.category,
        "reason": message,
        "details": [message],
        "rollback_target": rule.rollback_target,
        "revision_action": rule.revision_action,
        "auto_fixable": rule.auto_fixable,
    }


def build_review_failure(
    check: str, message: str, fallback_target: str = "report"
) -> dict[str, Any]:
    """Create one safe, serializable review failure for another review stage."""
    return _failure(check, message, fallback_target)


def select_review_failure(failures: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Choose the earliest broken layer, preserving the actual rule metadata."""
    if not failures:
        return None
    return min(
        failures,
        key=lambda item: (
            ROLLBACK_PRIORITY.index(item.get("rollback_target", "report"))
            if item.get("rollback_target") in ROLLBACK_PRIORITY
            else len(ROLLBACK_PRIORITY),
            0 if item.get("severity") == "BLOCKING" else 1,
        ),
    )


def _positive_claim(report: str, patterns: tuple[str, ...]) -> bool:
    def is_quoted(position: int) -> bool:
        prefix = report[:position]
        if any(prefix.count(marker) % 2 for marker in ('"', "'", "`")):
            return True
        return any(
            report.rfind(open_quote, 0, position)
            > report.rfind(close_quote, 0, position)
            for open_quote, close_quote in (("“", "”"), ("「", "」"), ("『", "』"))
        )

    for pattern in patterns:
        for match in re.finditer(pattern, report, re.IGNORECASE):
            # Scope qualifiers to the current Markdown sentence/clause.  A
            # previous independent clause such as "没有 2xx" must not hide a
            # later contradiction such as "业务结果未知".
            start = max(
                report.rfind(delimiter, 0, match.start())
                for delimiter in ("。", "！", "？", "!", "?", "\n", "；", ";")
            ) + 1
            end_candidates = [
                report.find(delimiter, match.end())
                for delimiter in ("。", "！", "？", "!", "?", "\n", "；", ";")
                if report.find(delimiter, match.end()) >= 0
            ]
            end = min(end_candidates) if end_candidates else len(report)
            clause = report[start:end]
            prefix = clause[: match.start() - start]
            # Knowledge citations and policy prose often quote the very claim
            # words that the report is required to check.  A quoted example is
            # not a current-event assertion; it must not turn a safe report
            # into REVIEW FAILED.
            if is_quoted(match.start()):
                continue
            clause_without_match = prefix + clause[match.end() - start :]
            if (
                any(context in prefix for context in NEUTRAL_CONTEXTS)
                or "是否" in prefix
                or any(
                    context in clause_without_match for context in CONSTRAINT_CONTEXTS
                )
            ):
                continue
            if not any(negation in prefix for negation in NEGATIONS):
                return True
    return False


def _layer(assessment: dict[str, Any], layer_id: str) -> dict[str, Any]:
    return next(
        (item for item in assessment.get("layers", []) if item.get("id") == layer_id),
        {},
    )


def _review_result(
    failures: list[dict[str, Any]],
    checks: list[dict[str, Any]],
    *,
    conflicts: list[dict[str, Any]] | None = None,
    stage: str = "semantic_review",
    reviewed_final_report: bool = True,
) -> dict[str, Any]:
    conflicts = conflicts or []
    if failures:
        primary = select_review_failure(failures) or failures[0]
        categories = list(
            dict.fromkeys(
                str(item.get("error_category", "UNKNOWN_ERROR"))
                for item in failures
            )
        )
        return {
            "stage": stage,
            "status": "FAIL",
            "approved": False,
            "failures": failures,
            "checks": checks,
            "failure_rules": [item["rule_id"] for item in failures],
            "issues": [item["reason"] for item in failures],
            "failure_details": [item["details"] for item in failures],
            "error_category": primary.get("error_category", "UNKNOWN_ERROR"),
            "failure_type": primary.get("failure_type", "UNKNOWN_ERROR"),
            "error_categories": categories,
            "error_scope": (
                "analysis"
                if any(
                    item.get("rollback_target") in ANALYSIS_ROLLBACK_TARGETS
                    for item in failures
                )
                else "report"
            ),
            "failure_reason": "; ".join(
                str(item.get("reason", "")) for item in failures[:4]
            ),
            "rollback_target": primary["rollback_target"],
            "revision_action": primary["revision_action"],
            "reviewed_final_report": reviewed_final_report,
            "conflicts": conflicts,
        }
    return {
        "stage": stage,
        "status": "PASS",
        "approved": True,
        "failures": [],
        "checks": checks,
        "failure_rules": [],
        "issues": [],
        "failure_details": [],
        "error_category": None,
        "failure_type": None,
        "error_categories": [],
        "error_scope": "none",
        "failure_reason": "",
        "rollback_target": None,
        "revision_action": "无需回退；允许交付。",
        "reviewed_final_report": reviewed_final_report,
        "conflicts": conflicts,
    }


def semantic_review(
    raw_alert: dict[str, Any] | str,
    normalized_event: dict[str, Any],
    business_context: dict[str, Any],
    scene_result: dict[str, Any],
    evidence: dict[str, Any],
    risk_result: dict[str, Any],
    final_report_text: str,
    *,
    router: dict[str, Any] | None = None,
    evidence_store: dict[str, Any] | None = None,
    security_result: dict[str, Any] | None = None,
    workflow_result: dict[str, Any] | None = None,
    include_report_checks: bool = True,
    state_version: int | None = None,
    generated_from_state_version: int | None = None,
) -> dict[str, Any]:
    """Return PASS/FAIL and an explicit rollback target.

    The raw alert is accepted to keep the review contract complete, but review
    decisions use normalized fields and structured upstream state.  The report
    text is always checked as a separate input so a correct State cannot mask a
    wrong Markdown statement.
    """
    del raw_alert  # kept in the contract for audit tooling; never treated as instructions
    report = str(final_report_text or "")
    failures: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    def check(
        check_id: str,
        passed: bool,
        message: str,
        rollback_target: str = "report",
    ) -> None:
        checks.append({"id": check_id, "status": "PASS" if passed else "FAIL", "message": message})
        if not passed:
            failures.append(_failure(check_id, message, rollback_target))

    http_status = normalized_event.get("http", {}).get("status_code")
    business_success = normalized_event.get("business_result", {}).get("success")
    if include_report_checks:
        no_2xx_claim = _positive_claim(
            report,
            (r"无\s*(?:有效\s*)?2xx", r"没有\s*2xx", r"未(?:观察到|发现|见)\s*2xx", r"不存在\s*2xx"),
        )
        check(
            "http_status_matches_report",
            not (http_status is not None and 200 <= int(http_status) < 300 and no_2xx_claim),
            "报告必须保留已观察到的 HTTP 2xx 状态，不得写成没有 2xx。",
            "report",
        )
        unknown_business = _positive_claim(report, (r"业务结果未知", r"business[_ ]result\s*(?:is\s*)?unknown"))
        check(
            "business_result_matches_report",
            not (business_success is True and unknown_business),
            "business_result.success=true 时，报告不能把业务结果写成未知。",
            "report",
        )

    context_id = business_context.get("context_id")
    context_confidence = business_context.get("confidence_score")
    check(
        "business_context_is_structured",
        bool(context_id) and isinstance(context_confidence, (int, float)) and 0 <= float(context_confidence) <= 1,
        "业务上下文必须包含开放 taxonomy 的 context_id 和 0–1 数值置信度。",
        "business_context",
    )

    auth = normalized_event.get("authorization", {})
    not_applicable = normalized_event.get("field_applicability", {}).get("not_applicable_fields", [])
    if include_report_checks:
        auth_missing_claim = _positive_claim(
            report,
            (r"未观察到\s*(?:Authorization|认证|Cookie|Session)", r"未提供\s*(?:Authorization|认证|Cookie|Session)"),
        )
        check(
            "authorization_matches_report",
            not (bool(auth.get("present")) and auth_missing_claim),
            "Authorization/Cookie 存在时，报告必须说明已观察到字段并保留其有效性未确认边界。",
            "report",
        )
        false_only_claim = _positive_claim(
            report,
            (r"攻击(?:行为|已经)?发生", r"攻击成功", r"行为存在", r"已执行", r"确认执行"),
        )
        mentioned_not_applicable = any(
            str(field).split(".")[-1].lower() in report.lower() for field in not_applicable
        )
        check(
            "field_applicability_is_respected",
            not (not_applicable and mentioned_not_applicable and false_only_claim),
            "不适用字段的 0/false 不能被报告解释成攻击行为或负证据。",
            "report",
        )

    selected = scene_result.get("selected_scene") or scene_result.get("primary_scenario") or {}
    scene_id = str(selected.get("scene_id") or scene_result.get("scene_id") or "generic")
    action = str(business_context.get("action") or "unknown")
    normal_auth = (
        action == "authentication"
        and business_context.get("normal_behavior_assessment") == "normal_business_consistent"
        and not business_context.get("deviation")
    )
    check(
        "scene_matches_business_context",
        not (scene_id == "data_exposure" and normal_auth and not business_context.get("token_leak_signal")),
        "正常登录成功返回当前主体 Token/Session 不能自动升级为数据泄露场景。",
        "scene_classification",
    )

    if router:
        selected_problem = str(
            (security_result or {}).get("candidates", [{}])[0].get("scene_id")
            if (security_result or {}).get("candidates")
            else selected.get("security_problem_id") or router.get("selected_scene_id") or "unknown"
        )
        check(
            "router_matches_security_problem",
            selected_problem == str(router.get("selected_scene_id") or selected_problem),
            "Router 的 selected_scene_id 必须与安全问题分类器的主候选一致。",
            "workflow_router",
        )
        check(
            "workflow_is_registered",
            bool(router.get("workflow_id") and router.get("risk_profile_id") and router.get("workflow")),
            "Router 必须输出已注册 Workflow、risk_profile_id 及专用策略。",
            "workflow_router",
        )
        if evidence_store:
            known = {str(item.get("evidence_id")): item for item in evidence_store.get("items", [])}
            unsupported: list[str] = []
            for support in (security_result or {}).get("candidates", [{}])[0].get("support", []):
                evidence_id = str(support.get("evidence_id")) if isinstance(support, dict) else ""
                item = known.get(evidence_id)
                provenance = item.get("provenance", {}) if item else {}
                if not item or not (
                    item.get("applicable")
                    and provenance.get("describes_current_event")
                    and provenance.get("event_layer") == 0
                ):
                    unsupported.append(evidence_id or "missing")
            check(
                "main_scene_uses_current_evidence",
                not unsupported,
                f"主场景支持只能引用当前事件 layer=0 的 Evidence ID；无效引用：{', '.join(unsupported[:6]) or '无'}。",
                "security_classification",
            )
        if workflow_result:
            check(
                "workflow_contract_is_bound",
                workflow_result.get("workflow_id") == router.get("workflow_id")
                and bool(workflow_result.get("evidence_schema")),
                "专用 Workflow 证据契约必须绑定 Router 选择且包含 evidence schema。",
                "workflow_evidence",
            )
        eligibility = router.get("eligibility") or {}
        if workflow_result:
            eligibility = workflow_result.get("eligibility") or eligibility
        check(
            "workflow_is_eligible",
            bool(eligibility.get("eligible", True)),
            str(eligibility.get("reason") or "所选 Workflow 缺少兼容的当前事件证据。"),
            "workflow_router",
        )

    risk_scene_id = str(risk_result.get("scene_id") or risk_result.get("risk_profile", {}).get("scene_id") or "")
    check(
        "risk_profile_matches_scene",
        not risk_scene_id or risk_scene_id == scene_id,
        f"风险 Profile ({risk_scene_id or '缺失'}) 必须与主场景 ({scene_id}) 一致。",
        "risk",
    )
    if router:
        check(
            "risk_profile_matches_router",
            str(risk_result.get("risk_profile_id") or "") == str(router.get("risk_profile_id") or ""),
            "Risk Agent 必须使用 Router 选定的 risk_profile_id，不得二次猜测场景。",
            "risk",
        )

    if include_report_checks:
        if scene_id == "data_exposure":
            sql_fix_claim = _positive_claim(report, (r"参数化查询", r"SQL\s*注入.*修复", r"动态\s*SQL"))
            check(
                "remediation_matches_scene",
                not sql_fix_claim,
                "敏感数据暴露场景的修复建议应围绕身份、Session、对象级授权和最小化返回。",
                "report",
            )
        else:
            checks.append({"id": "remediation_matches_scene", "status": "PASS", "message": "无需执行数据暴露专用修复冲突检查。"})

    if include_report_checks:
        exploitation = _layer(scene_result.get("event_assessment", {}), "further_exploitation")
        authorization = _layer(scene_result.get("event_assessment", {}), "authorization")
        direct_exploitation = exploitation.get("status") == "✅ 已覆盖"
        direct_authorization = authorization.get("status") == "✅ 已覆盖"
        unsupported_success = _positive_claim(report, SUCCESS_CLAIM_PATTERNS)
        check(
            "security_claims_have_evidence",
            not (unsupported_success and not (direct_exploitation or direct_authorization)),
            "攻击成功、成功利用、数据外泄或未授权访问成功等结论必须有对应直接证据。",
            "report",
        )

    # A direct evidence conflict is itself a review failure, even when the
    # report is cautious.  It prevents REVIEW PASSED from hiding upstream data
    # quality problems.
    context_conflicts = business_context.get("semantic_conflicts", [])
    conflicts = list(context_conflicts) if isinstance(context_conflicts, list) else []
    if evidence.get("conflicts", 0) and not conflicts:
        conflicts = list(normalized_event.get("semantic_conflicts", []))
    check(
        "upstream_state_is_consistent",
        not bool(evidence.get("conflicts", 0) or normalized_event.get("semantic_conflicts")),
        "上游规范化/字段语义存在冲突，必须在交付前保留 REVIEW FAILED。",
        "normalization",
    )

    if include_report_checks and state_version is not None and generated_from_state_version is not None:
        check(
            "report_state_version_matches",
            state_version == generated_from_state_version,
            f"报告必须由当前 State Version {state_version} 生成，实际为 {generated_from_state_version}。",
            "report",
        )
    return _review_result(
        failures,
        checks,
        conflicts=conflicts,
        stage="semantic_review",
        reviewed_final_report=include_report_checks,
    )


def structured_state_review(
    raw_alert: dict[str, Any] | str,
    normalized_event: dict[str, Any],
    business_context: dict[str, Any],
    scene_result: dict[str, Any],
    evidence: dict[str, Any],
    risk_result: dict[str, Any],
    *,
    router: dict[str, Any] | None = None,
    evidence_store: dict[str, Any] | None = None,
    security_result: dict[str, Any] | None = None,
    workflow_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Review structured state before any report is generated.

    This stage deliberately does not inspect report text, headings, citations,
    or model wording.  A failure here must rerun the owning upstream node.
    """
    result = semantic_review(
        raw_alert,
        normalized_event,
        business_context,
        scene_result,
        evidence,
        risk_result,
        "",
        router=router,
        evidence_store=evidence_store,
        security_result=security_result,
        workflow_result=workflow_result,
        include_report_checks=False,
    )
    result["stage"] = "structured_state_review"
    result["reviewed_final_report"] = False
    return result


def _has_heading(report: str, section: str) -> bool:
    """Require a real Markdown heading while tolerating harmless spacing."""
    expected_values = SECTION_ALIASES.get(str(section), (str(section),))
    expected = {
        re.sub(r"[\s`*_~]", "", value.strip()).casefold()
        for value in expected_values
    }
    for match in re.finditer(r"(?m)^\s*#{1,6}\s*(.+?)\s*$", report):
        heading = re.split(r"[：:（(【\[-]", match.group(1), maxsplit=1)[0]
        actual = re.sub(r"[\s`*_~]", "", heading).casefold()
        if actual in expected:
            return True
    return False


def report_policy_check(
    report: str,
    *,
    required_sections: tuple[str, ...] | list[str] = (),
    known_knowledge_ids: set[str] | None = None,
    known_evidence_ids: set[str] | None = None,
    chart_ids: list[str] | None = None,
    minimum_characters: int = 2_400,
    state_version: int | None = None,
    generated_from_state_version: int | None = None,
) -> dict[str, Any]:
    """Review report-only policy and references after structured State passed."""
    text = str(report or "")
    failures: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    def check(check_id: str, passed: bool, message: str) -> None:
        checks.append(
            {"id": check_id, "status": "PASS" if passed else "FAIL", "message": message}
        )
        if not passed:
            failures.append(_failure(check_id, message, "report"))

    missing = [section for section in required_sections if not _has_heading(text, section)]
    check(
        "required_report_sections",
        not missing,
        f"报告缺少语义章节标题：{', '.join(missing)}" if missing else "报告章节标题完整。",
    )
    meets_minimum = len(text) >= minimum_characters
    check(
        "report_minimum_structure",
        meets_minimum,
        (
            f"报告长度 {len(text)} 达到最小要求 {minimum_characters} 字符。"
            if meets_minimum
            else f"报告长度 {len(text)} 小于最小要求 {minimum_characters} 字符。"
        ),
    )

    known_knowledge_ids = known_knowledge_ids or set()
    referenced_knowledge = set(re.findall(r"\[(K-\d+)\]", text))
    unknown_knowledge = referenced_knowledge - known_knowledge_ids
    check(
        "report_knowledge_references",
        not unknown_knowledge and (not known_knowledge_ids or bool(referenced_knowledge)),
        "报告知识引用必须来自本次检索结果，且在有知识结果时至少引用一条。",
    )

    known_evidence_ids = known_evidence_ids or set()
    referenced_evidence = set(re.findall(r"\bE\d{3,}\b", text))
    unknown_evidence = referenced_evidence - known_evidence_ids
    check(
        "report_evidence_references",
        not unknown_evidence,
        "报告只能引用当前 Evidence Store 中存在的 Evidence ID。",
    )

    chart_ids = chart_ids or []
    missing_charts = [
        chart_id for chart_id in chart_ids if f"<!-- chart:{chart_id} -->" not in text
    ]
    check(
        "report_chart_markers",
        not missing_charts,
        f"报告缺少图表标记：{', '.join(missing_charts)}" if missing_charts else "图表标记完整。",
    )
    if state_version is not None and generated_from_state_version is not None:
        check(
            "report_state_version_matches",
            state_version == generated_from_state_version,
            f"报告必须由当前 State Version {state_version} 生成，实际为 {generated_from_state_version}。",
        )

    result = _review_result(
        failures,
        checks,
        stage="report_policy_check",
        reviewed_final_report=True,
    )
    result["missing_sections"] = missing
    result["unknown_knowledge_ids"] = sorted(unknown_knowledge)
    result["unknown_evidence_ids"] = sorted(unknown_evidence)
    result["missing_chart_ids"] = missing_charts
    return result
