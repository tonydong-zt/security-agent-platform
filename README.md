# AI 安全运营智能体平台

这是一个防御性安全运营项目，用于上传安全文档、日志和告警文本，并通过 Chroma RAG、LangChain、LangGraph、LLM 和真实工具链完成告警调查、日志关联、风险研判、处置建议和事件报告生成。

项目原则：

- 不写死分析结果。
- 不伪造封禁、隔离、阻断、删除等真实动作。
- 未配置 LLM 时，Agent 明确失败。
- 未配置 Embedding 时，不能构建知识库。
- 未配置 SIEM/EDR/防火墙 API 时，只生成建议，不声称已经执行。
- Chroma 知识库为空时，会明确提示需要先上传文档或抓取公开安全资料。

## 目录结构

```text
security-agent-platform/
  backend/
    app/
      main.py
      config.py
      database.py
      agents/
      rag/
      routers/
      tools/
      integrations/
      models/
      schemas/
      services/
    tests/
    requirements.txt
    Dockerfile
  frontend/
    src/
      pages/
      components/
      api/
      types/
    package.json
    Dockerfile
  data/
    raw/
    logs/
    public_security/
    processed/
    chroma/
  scripts/
  .env.example
  environment.yml
  docker-compose.yml
  GEMINI_EMBEDDING.md
```

## 第 0 步：重要安全提醒

不要把真实 API Key 发到聊天窗口、截图、Git 仓库或 README。

如果你的 DeepSeek Key 或 Gemini Key 已经出现在截图或聊天里，请立刻去对应控制台删除或重置，然后换新 key 写入 `.env`。

## 第 1 步：准备环境

推荐使用 conda：

```powershell
cd C:\Users\19801\Documents\Codex\2026-07-08\qing\security-agent-platform
conda env create -f environment.yml
conda activate security-agent-platform
```

如果你不用 conda，也可以使用 venv：

```powershell
cd C:\Users\19801\Documents\Codex\2026-07-08\qing\security-agent-platform
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
```

前端依赖：

```powershell
cd C:\Users\19801\Documents\Codex\2026-07-08\qing\security-agent-platform\frontend
npm install
```

## 第 2 步：创建 .env

项目读取的是 `.env`，不是 `.env.example`。

```powershell
cd C:\Users\19801\Documents\Codex\2026-07-08\qing\security-agent-platform
copy .env.example .env
notepad .env
```

`.env.example` 是模板，真实 key 只放 `.env`。`.env` 已经在 `.gitignore` 中，不应该提交。

## 第 3 步：填写 DeepSeek LLM

如果你使用 DeepSeek：

```env
LLM_PROVIDER=deepseek

LLM_API_KEY=
LLM_BASE_URL=
LLM_MODEL=

LLM_TEMPERATURE=0.2
LLM_TIMEOUT_SECONDS=60

DEEPSEEK_API_KEY=你的新DeepSeek_API_Key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=你账号可用的DeepSeek模型名
DEEPSEEK_THINKING_ENABLED=true
DEEPSEEK_REASONING_EFFORT=high
```

说明：

- `LLM_PROVIDER=deepseek` 时，后端读取 `DEEPSEEK_*` 这组配置。
- `LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL` 是给 `LLM_PROVIDER=openai_compatible` fallback 用的，DeepSeek 模式下可以留空。
- `DEEPSEEK_MODEL` 不要瞎填，必须是你账号当前可用的真实模型名。
- 如果模型或接口不支持 reasoning 参数，把 `DEEPSEEK_THINKING_ENABLED=false`。

如果以后你改用其他 OpenAI-compatible 服务：

```env
LLM_PROVIDER=openai_compatible
LLM_API_KEY=你的API_Key
LLM_BASE_URL=你的OpenAI兼容base_url
LLM_MODEL=你的模型名
```

## 第 4 步：填写 Embedding

知识库入库必须配置 Embedding。你现在想用 Gemini，推荐这样填：

```env
EMBEDDING_PROVIDER=gemini

EMBEDDING_API_KEY=
EMBEDDING_BASE_URL=
EMBEDDING_MODEL=
LOCAL_EMBEDDING_MODEL=

GEMINI_API_KEY=你的Google_Gemini_API_Key
GEMINI_EMBEDDING_MODEL=gemini-embedding-001
GEMINI_EMBEDDING_TASK_TYPE=RETRIEVAL_DOCUMENT
GEMINI_EMBEDDING_OUTPUT_DIMENSION=
```

说明：

- `EMBEDDING_PROVIDER=gemini` 时，后端调用 Google Gemini 原生 embedding API。
- 不要把 Gemini 原生 API 地址填到 `EMBEDDING_BASE_URL`。
- `EMBEDDING_BASE_URL` 只给 OpenAI-compatible `/embeddings` 服务使用。
- `GEMINI_EMBEDDING_MODEL` 必须是你 Google 账号可用的 embedding 模型。
- `GEMINI_EMBEDDING_OUTPUT_DIMENSION` 可以留空。

如果你使用 OpenAI-compatible embedding 中转：

```env
EMBEDDING_PROVIDER=openai_compatible
EMBEDDING_API_KEY=你的Embedding_API_Key
EMBEDDING_BASE_URL=你的OpenAI兼容embedding_base_url
EMBEDDING_MODEL=你的embedding模型名
```

如果你使用本地 sentence-transformers：

```env
EMBEDDING_PROVIDER=local
LOCAL_EMBEDDING_MODEL=你的本地模型名或路径
```

本地 embedding 会占用本机 CPU/GPU，可能比云 API 慢。

## 第 5 步：数据库和 Chroma

本地快速测试可以这样保留：

```env
DATABASE_URL=
CHROMA_PERSIST_DIR=./data/chroma
CHROMA_COLLECTION_NAME=security_knowledge
```

`DATABASE_URL=` 留空时，后端自动使用 SQLite fallback：

```text
./data/security_agent.db
```

如果要使用 PostgreSQL：

```env
DATABASE_URL=postgresql+psycopg://用户名:密码@数据库地址:5432/数据库名
```

## 第 6 步：外部安全工具配置

没有真实 SIEM/EDR/防火墙 API 时，全部留空：

```env
SIEM_API_URL=
SIEM_API_KEY=
SIEM_VENDOR=

EDR_API_URL=
EDR_API_KEY=
EDR_VENDOR=

FIREWALL_API_URL=
FIREWALL_API_KEY=
FIREWALL_VENDOR=
```

留空时系统不会执行真实查询、封禁、隔离或阻断，只会返回建议或 `tool_not_configured`。

## 第 7 步：初始化数据库

```powershell
cd C:\Users\19801\Documents\Codex\2026-07-08\qing\security-agent-platform
$env:PYTHONPATH="backend"
python scripts\init_db.py
```

## 第 8 步：启动后端

```powershell
cd C:\Users\19801\Documents\Codex\2026-07-08\qing\security-agent-platform
$env:PYTHONPATH="backend"
uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000
```

检查健康状态：

```powershell
curl http://127.0.0.1:8000/api/health
```

正常情况下你应该看到：

```json
{
  "backend": "ok",
  "database": "ok",
  "llm": "ok",
  "embedding": "ok"
}
```

如果 `embedding=missing_config`，说明 Gemini 或其他 embedding 配置没填完整。

如果 `chroma=empty`，这是正常的，表示你还没有上传知识库文档。

## 第 9 步：启动前端

新开一个 PowerShell：

```powershell
cd C:\Users\19801\Documents\Codex\2026-07-08\qing\security-agent-platform\frontend
npm run dev
```

浏览器访问：

```text
http://127.0.0.1:5173
```

如果前端部署到服务器，需要设置：

```env
VITE_API_BASE_URL=https://你的后端域名
```

否则前端开发模式默认访问：

```text
http://localhost:8000
```

## 第 10 步：上传知识库文档

在前端打开 `Knowledge Base` 页面：

1. 上传 PDF、TXT、MD、CSV、JSON 或 LOG 文件。
2. 后端会解析文本。
3. 文本会切分成 chunks。
4. Gemini embedding 会把 chunks 转成向量。
5. Chroma 保存向量和 metadata。
6. 页面返回真实 chunk 数量。

如果 Embedding 没配好，上传会失败，不会假装成功。

## 第 11 步：上传日志

在前端打开 `Log Upload` 页面：

1. 上传 `.log`、`.txt`、`.json` 或 `.csv` 日志。
2. 系统会保存原始日志。
3. 系统会尝试解析：
   - timestamp
   - source_ip
   - destination_ip
   - username
   - hostname
   - process_name
   - event_type
   - message
4. 解析失败的行也会保存 `raw_message`。

## 第 12 步：发起调查

在前端打开 `Investigation` 页面：

1. 输入问题，例如 `请分析这条告警`。
2. 粘贴告警文本。
3. 勾选是否使用日志和知识库。
4. 点击开始。

系统会真正运行 LangGraph Agent：

```text
validate_runtime_config
intent_classification
entity_extraction
evidence_collection
rag_retrieval
threat_analysis
tool_decision
action_planning
human_approval_check
report_generation
```

页面会显示：

- Agent trace
- 日志匹配结果
- RAG 检索结果
- 工具调用记录
- 风险等级
- 建议动作
- Markdown 事件报告

## 第 13 步：人工审批动作

在 `Action Approval` 页面审批高危动作。

没有真实外部 API 时，执行会失败并返回：

```json
{
  "status": "failed",
  "code": "tool_not_configured"
}
```

这是正确行为，不是错误。系统不会伪造真实动作成功。

## Docker Compose 启动

```powershell
cd C:\Users\19801\Documents\Codex\2026-07-08\qing\security-agent-platform
copy .env.example .env
notepad .env
docker compose up --build
```

注意：`docker-compose.yml` 里的 PostgreSQL 密码只是本地示例，生产环境必须替换。

## 测试

安装依赖后运行：

```powershell
cd C:\Users\19801\Documents\Codex\2026-07-08\qing\security-agent-platform
$env:PYTHONPATH="backend"
pytest backend\tests
```

测试覆盖：

- health 配置缺失检查。
- Gemini embedding 缺失配置检查。
- Chroma 空库检索。
- 文档上传。
- 日志上传解析。
- LLM 未配置时调查明确失败。
- Mock LLM 下 LangGraph 节点执行。
- 防火墙未配置时返回 `tool_not_configured`。
- 未配置外部动作不允许假成功。

## 如何验证不是固定假回复

1. 上传不同知识库文档，检索不同关键词，看 chunk、source、score 是否变化。
2. 上传不同日志，调查不同 IP、用户名、主机和进程，看日志匹配是否变化。
3. 发起不同告警调查，看实体提取、RAG 检索、工具调用、风险等级和报告内容是否变化。
4. 不上传知识库时，系统会提示知识库为空。
5. 不上传日志时，系统会提示未发现可用日志。
6. 不配置外部 API 时，动作审批返回 `tool_not_configured`。

## 常见问题

### `.env.example` 改了为什么没生效？

程序读取 `.env`，不是 `.env.example`。你需要把配置写到 `.env`，然后重启后端。

### 为什么有 localhost？

`localhost` 只是本地开发默认值。部署到服务器时，把前端的 `VITE_API_BASE_URL` 改成后端域名，并让后端监听 `0.0.0.0`。

### 为什么 Chroma 是 empty？

说明还没有上传知识库文档。先去 `Knowledge Base` 上传资料。

### 为什么 Action Approval 不能执行？

如果 EDR 或 Firewall API 没配置，系统会禁用或返回 `tool_not_configured`。这是为了避免伪造执行结果。

## 后续你需要补充的真实内容

- DeepSeek API Key。
- DeepSeek base URL。
- DeepSeek 模型名。
- Gemini API Key。
- Gemini embedding 模型名。
- 真实安全文档。
- 真实安全日志。
- SIEM API 文档。
- EDR API 文档。
- 防火墙 API 文档。
- 服务器部署地址、数据库账号、TLS 和反向代理配置。

## 防御性安全边界

本项目只用于告警调查、日志分析、风险研判、处置建议、人工审批后的防御性动作和报告生成。

本项目不实现：

- 漏洞利用代码。
- 攻击载荷生成。
- 恶意代码生成。
- 绕过检测。
- 凭据窃取。
- 未授权扫描。
- 真实攻击自动化。
