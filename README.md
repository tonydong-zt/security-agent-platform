# AI Security Agent Workbench｜本地安全研判平台

这是一个在 Windows 本机运行的 FastAPI + React 安全研判平台。新版加入了可审计多 Agent 链路、用户可控的本地记忆、GFM Markdown 报告、安全图表渲染和多模型供应商路由；研判必须经过真实的 LangChain LLM 推理链。未配置模型时仅可使用知识检索和独立工具工作台，不能生成研判报告。

## 直接运行

前提：Windows 10/11，安装 Python 3.11、3.12 或 3.13。

任选一种方式：

1. 双击 `启动安全智能体平台.bat`；
2. 在 VS Code 中运行任务“启动完整平台”；
3. 在 PowerShell 中运行 `./start.ps1`。

启动后访问 <http://127.0.0.1:8090>，按 `Ctrl+C` 停止。首次运行会自动创建 `.venv` 并安装后端依赖；前端和 Chroma 知识库已构建完成。

启动脚本会验证 `.venv` 是否可运行。若发现从其他电脑或路径复制而来的无效环境，它会将其改名为 `.venv-invalid-时间戳`，再使用本机 Python 重建，不需要手工删除。

## 多 Agent 协作链路

每次研判由 LangChain LCEL RunnableSequence 编排；模型调用使用 ChatPromptTemplate → CompatibleChatModel（BaseChatModel 原生异步适配器）：

`规划 Agent → 证据/分类/路由 Agent → 记忆 Agent → 风险 Agent → 结构化 State Review → 报告 Agent → 最终报告 Review`

| Agent | 职责 | 主要输出 |
| --- | --- | --- |
| 规划 Agent | 明确待验证问题和执行顺序 | 研判目标与计划 |
| 证据 Agent | 分离业务上下文与安全问题，完成证据 Store、Router 和场景工具选择 | 双层候选、Workflow 路由、九层事件判断、安全实体分类、语义化 IOC、有效时间线 |
| 记忆 Agent | 在场景与 Workflow 选定后检索经用户授权的历史经验 | 仅供参考的经验提示，不改变当前证据 |
| 风险 Agent | 工具整理证据和规则风险分，再由 LLM 独立研判 | 模型结论、场景、置信度、当前 Evidence ID 引用、历史反馈自检 |
| 报告 Agent | 必须调用 LLM，基于结构化研判和证据撰写报告 | 模型生成的 Markdown；图表数据来自工具 |
| 结构化 State Review | 在报告生成前检查规范化、业务上下文、场景、路由、Workflow 证据契约和风险 Profile | 上游失败按最早责任层回滚，不生成报告 |
| 最终报告 Review | 独立 LLM 复核，并叠加报告事实、引用、章节、图表及语义检查 | 通过才交付；最多两轮修正，重复无进展会记录循环诊断 |

研判结果页会展示每个 Agent 的目标、工具、输入/输出摘要、状态和耗时。这是供审计与复核的决策轨迹，不展示模型私密思维链、隐藏提示词或敏感凭据。

实际运行时，证据 Agent 按 `Semantic Normalization → Business Context → Security Problem → Workflow Router → Scene Workflow` 执行。业务上下文输出开放 taxonomy 的 `context_id` 与数值置信度，安全问题分类器输出可含 `OTHER/unknown` 的候选集；候选支持只引用 Unified Evidence Store 的 `evidence_id`。Router 从 10 类 Workflow 中选择 primary/secondary 和 `risk_profile_id`，只执行选中 Workflow 的工具计划；Risk Agent 直接使用该 Profile。报告前的 State Review 与报告后的最终 Review 分离：上游状态错误不能由重写 Markdown 修复，报告事实/引用/结构问题只回退报告层。每次修订递增 `state_version`，记录结构化 State/报告哈希、失败规则、错误类别、回滚目标和修订动作；重复无进展会记录 `REVIEW_REPAIR_LOOP_DETECTED` 诊断并拒绝交付。仍未通过则返回 HTTP 502，不记录 completed，也不交付报告。工具 Router 仍是确定性证据收集路由，不是最终模型结论；摘要的场景、结论与置信度来自 LLM，风险分数明确标为工具指标。

排障时可在启动 FastAPI 进程前设置 `ANALYSIS_DEBUG=true`。此时 `/api/analyze` 额外返回 `debug_trace`，包括规范化事件（敏感值仅保留元数据）、业务上下文、安全问题候选、Router Trace、Workflow 证据契约、统一证据 Store（当前事件/嵌入/历史 provenance）、RiskProfile、知识查询和引用 ID、结构化 State Review、最终报告 Review、State Version/哈希、回退、模型调用错误与阶段事件；默认关闭，前端也只在该字段存在时显示 Trace 面板。复核失败接口会返回安全的诊断摘要，前端展示错误类别、规则、回滚层和修订动作，不展示报告正文或敏感上下文。

### 双层分类与路由边界

- Business Context 只回答“业务正在做什么”：认证、登出、改密、资源读写、文件上传/下载、配置/日志访问、数据库操作、进程执行、网络、云/容器等；它不等于攻击结论。
- Security Problem 只回答“可能存在什么安全问题”：弱凭据、暴力破解、未授权访问、敏感数据暴露、SQL 注入、命令注入、RCE、XSS、SSRF、路径穿越、文件/样本、扫描、横向、持久化、外传、配置错误、可疑/正常/未知等，并保留开放世界候选。
- `backend/app/workflows.py` 的 Registry 为认证、授权、Web 攻击、文件、数据暴露、主机、网络、数据库、云和通用异常维护工具、证据 schema、风险 Profile、知识策略、修复和验证策略。低置信度/未知候选统一回退 `generic_workflow`。
- `backend/app/evidence_store.py` 将当前事件固定为 layer 0，嵌入日志/请求/响应工件为 layer 1，历史或参考内容为 layer 2；只有 `describes_current_event=true` 且 `event_layer=0` 的证据可直接支持主场景。HTTP 200、命令字符串、文件名、缺失 Authorization 和响应敏感字段分别不能越权推出执行、恶意、未授权或外传。

## Agent 工具层

平台注册十八个只读工具；每次研判只执行 Router 选定 Workflow 的相关工具：

| 工具 | 功能 | 输出 |
| --- | --- | --- |
| `normalize_alert` | 解析 HTTP 请求/响应、状态、认证、时间和网络字段 | 脱敏规范化事件；协议状态与业务结果分开；非适用字段标注 |
| `infer_business_context` | 根据接口、方法、请求/响应语义推断业务动作和正常预期 | 业务动作/对象、观察行为、偏差、正/反证据和置信度 |
| `build_evidence_store` | 创建统一、脱敏、可追溯的 Evidence ID 与 event layer | raw/semantic 值、适用性、source role、当前事件 provenance |
| `classify_security_problems` | 对开放世界安全问题候选进行独立分类 | 候选、置信度、缺证、反证和 Evidence ID 支持 |
| `route_workflow` | 按上下文、安全问题、证据覆盖和置信度做确定性路由 | primary/secondary Workflow、工具计划和 `risk_profile_id` |
| `build_workflow_evidence` | 生成场景专用证据契约和补证策略 | evidence schema、缺口、知识、修复与验证策略 |
| `generate_scene_candidates` | 基于规范化事实和业务上下文生成竞争场景 | 支持/反对/缺失证据、业务适配度、证据强度和置信度 |
| `select_primary_scene` | 从候选中选择主场景 | `scene_id`、场景证据模板和主场景标记 |
| `assess_event_layers` | 分离确认事实、合理推断和未知项 | 请求、处理、业务响应、敏感返回、认证观察、授权、漏洞、利用与影响的九层判断 |
| `extract_iocs` | 仅在字段语义具备攻击关联时提取 IP、域名、URL、哈希和 CVE | IOC 意义、内部/私网范围、可信度与被排除的伪 IOC 候选 |
| `extract_security_entities` | 先进行安全实体分类 | 网络 IOC、文件/样本、资产、应用、技术栈、敏感数据、身份、漏洞与系统标识符 |
| `build_timeline` | 仅识别语义明确且有效的事件时间 | 可追溯时间线；`0`、空值和无效时间戳标记为未记录，不转换为 1970 年 |
| `evidence_matrix` | 检查证据状态和原始字段语义冲突 | ✅ 已覆盖、⚠️ 部分覆盖、❌ 缺失、⚡ 存在冲突与有效覆盖率 |
| `calculate_risk` | 先按主场景选择风险维度，再独立计算研判置信度 | 维度分数仅取 0/25/50/75/100 档位、场景化公式、字段证据和置信度 |
| `search_knowledge` | 检索内置 LangChain Chroma 集合 | 通过相关度门槛的文件、分块、检索相关度和引用 ID |
| `detect_contradictions` | 交叉检查 Agent 输出和原始字段语义 | 目标/Host、告警时间/HTTP Date、规则/响应语义及结构化结论冲突 |
| `build_report_charts` | 把工具结果转换为安全图表规范 | 条形图、环形图和时间线图 |
| `build_improvement_plan` | 将证据缺口转化为待审批的响应、恢复、沟通和能力改进计划 | 责任角色、时限、完成判据、关闭标准和路线图 |

“Agent 工具”页面可以从 React 前端单独调用每个工具并查看结构化 JSON 输入/输出。工具 API 为 `GET /api/tools` 和 `POST /api/tools/execute`，未知工具会被拒绝。

## 本地记忆与用户反馈

- 通过模型配置预检后的告警和需求，会先脱敏并追加记录到 `data/memory/inputs.jsonl`；研判结果会记录到 `data/memory/results.jsonl`。
- 用户可在每份报告下方点赞或点踩，并填写可选反馈；反馈写入 `data/memory/feedback.jsonl`。
- **只有选择点赞或点踩，并明确勾选“允许学习这条记录”**，系统才请求 LLM 提炼具体认可点/错误模式、修正原则、适用条件及下次核验步骤；成功且结构验证通过后，才作为正面或反面样例写入 `data/memory/learned_patterns.jsonl`；未勾选学习不会进入经验记忆。
- 无授权时只保存评价。无具体反馈、模型未配置、调用失败或无法提炼时，评价照常保存，界面明确显示尚未学习；不会后台自动重试。历史版本只保存评论的旧经验保留在磁盘，但不计入 LLM 已学习数量，也不自动召回。此处学习是检索记忆与提示自检，不是模型权重训练，也不保证完全避免重复错误。
- 被召回的经验始终标注为“仅作经验提示，不替代当前告警证据”；结论仍必须由当前输入、工具结果和知识库引用支持。
- “记忆与反馈”页面展示输入、反馈和已学习记录的数量，以及最近记录的状态。上述 JSONL 文件保留在本机且默认不纳入版本控制或交付压缩包。

## 可验证决策轨迹

研判结果会展示每一步的目标、工具名称、输入摘要、证据字段、输出摘要、状态和耗时。model_calls 默认返回，不依赖 Debug 开关，包含 evidence_reasoning、report_generation、report_review 的真实模型名称、耗时、状态和供应商提供的 token usage。token 数缺失时显示“供应商未返回”，不编造。这是适合审计和复核的决策轨迹，不展示模型私密思维链、隐藏提示词或敏感凭据。

## Markdown 与图表报告

- 使用 `react-markdown`、`remark-gfm` 和 `rehype-sanitize` 渲染标题、表格、列表、引用、代码块和链接；不执行报告中的原始 HTML 或脚本。
- 图表由后端返回结构化数据，React 在报告的 `<!-- chart:图表ID -->` 位置渲染，不执行模型生成的 JavaScript。
- LLM 报告必须覆盖确认事实、合理推断、尚未确认、动态候选场景（支持/反对/缺失证据）、九层事件成立判断、按场景选择的风险维度与可复算公式、独立置信度、四态证据矩阵、安全实体与 IOC 语义及排除项、有效/未记录且去重的时间线、字段语义冲突、关联排查、响应与恢复、沟通升级、关闭标准、修复与能力改进路线图、最终一致性自检、知识引用和 Agent 工具摘要。
- 场景识别不读取规则名称作为行为证据；认证失败、业务失败和敏感数据返回分别判断，HTTP 协议状态与业务状态分开呈现。报告长度和图表由有效证据复杂度决定，知识库只提供辅助依据，不替代当前事件证据。
- 知识检索在场景识别之后执行，查询由主/候选场景和非敏感行为字段构成；低相关片段会被质量门过滤，凭据类值不会进入检索词。
- 对未授权访问或敏感信息暴露场景，改进计划优先覆盖身份认证、Session 校验、对象级/功能级授权、敏感字段最小化返回、API Gateway/WAF、接口访问日志与账号行为审计；不会无依据套用 SQL 注入处置模板。
- 改进路线图包含根因与安全开发、检测与日志、资产与权限治理、流程与演练四类措施，并给出责任角色、建议时限和可度量的完成标准；所有内容都是待审批建议，不执行系统变更。
- 报告结构参考 [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) 的事件管理、分析、响应、恢复与改进思路；LLM 独立撰写并由另一次调用复核。没有本地报告基线和模板回退。
- 报告支持复制 Markdown 和下载 `.md`。

## 模型供应商

模型是研判的必备运行条件。没有 API Key 时后端返回 HTTP 503 MODEL_NOT_CONFIGURED，前端禁用研判按钮。use_model=false 或旧 use_deepseek=false 参数不能绕过；调用失败、截断、无效 JSON、证据引用错误或复核最终失败均拒绝交付。设置页支持：

- DeepSeek：默认 `deepseek-chat`，也可选择 `deepseek-reasoner`；
- OpenAI-compatible：填写兼容 Chat Completions 的模型名称和 API Key；
- 自定义兼容接口：可连接本机 `127.0.0.1`/`localhost` 模型或其他 HTTPS 服务。

API Key 只提交到本机 FastAPI 后端；选择持久化时写入 Windows 凭据管理器，不进入 `localStorage`、`sessionStorage` 或前端构建产物。也可复制 `.env.example` 为 `.env` 后配置 `MODEL_PROVIDER`、`MODEL_API_KEY`、`MODEL_NAME` 和 `MODEL_BASE_URL`。

## 知识库

- 集合：`security_knowledge`；
- 原始文档：50；
- 向量片段：2078；
- 嵌入：`local-security-hash-384`；
- 存储：项目内嵌 Chroma，不需要 PostgreSQL、MySQL、SQLite 业务库或独立 Chroma Server。

## 开发与验证

后端：

```powershell
$env:PYTHONPATH = (Resolve-Path ./backend).Path
./.venv/Scripts/python.exe -m ruff check ./backend
./.venv/Scripts/python.exe -m pytest ./backend/tests -q
```

当前回归为 76 项后端测试。LLM 测试在 HTTP 传输边界注入 MockTransport，实际经过 LCEL、模型适配器、提示与结构化解析；不代表真实供应商推理质量验证。涵盖无模型、绕过参数、三个阶段超时/401/空输出/截断、非法 JSON/证据引用、有限复核重试、正反反馈提炼及召回自检。测试隔离 Windows 凭据和个人 JSONL，绝不调用真实密钥。首次运行测试需安装 backend/requirements-dev.txt。

前端：

```powershell
cd frontend
pnpm install --frozen-lockfile
pnpm typecheck
pnpm build
```

实际供应商端到端验证仍需要用户配置并测试 API Key；本次仅验证了模拟模型完整路径与真实服务的缺模型拦截。

安全边界：平台工具层只读，不执行 Shell、CMD、PowerShell、任意文件写入、防火墙变更或进程终止。报告中的处置内容始终是建议，不代表已执行。
