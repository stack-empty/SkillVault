# QAX SUSPICIOUS 样本集（2026-06-02）

## 来源

- 原始压缩包：`sus_samples_20260602.zip`（用户本地存档）
- 导出工具：奇安信代码卫士 / 类似规则引擎（基于 50 类 `BEHAV_* / CQ_* / LLM_* / SECRET_* / PROMPT_INJECTION_* / SUPPLY_CHAIN_*` 规则）
- 导出日期：2026-06-02

## 内容

- **50 个 SHA1 命名的 skill 包**（每个独立 zip）
- **1 份 manifest**：`manifest_sus_20260602.csv`，列：
  - `files_sha1` — 文件集合 SHA1
  - `package_sha1` — 整个 skill 包 SHA1（作为 ID）
  - `skill_name` — skill 文件夹名
  - `verdict` — **全部为 `SUSPICIOUS`**（不是 `MALICIOUS`）
  - `primary_rule` — 主要命中的 QAX 规则名
  - `severity` — `HIGH`×34 / `MEDIUM`×5 / `LOW`×4 / `INFO`×5 / `CRITICAL`×1 / `NONE`×1

## 重要使用注意

⚠️ **`SUSPICIOUS` ≠ `MALICIOUS`**：

QAX 的 verdict 只是"可疑"，不是"确诊恶意"。这 50 个样本里很可能包含：
- 真实恶意（10-30%？需要人工复核）
- 误报 FP（合法工具被规则误命中）
- 边界灰色区（如合法运维工具用了高危原语）

历史上把这 50 个全标 `label=1 (malicious)` 是**标签膨胀**。新的 ground truth 建议改用 3 类：`SAFE / SUSPICIOUS / MALICIOUS`，保留 QAX 原意。

## QAX rule 覆盖（50 类 × 1 样本 / 类）

注意这是**规则覆盖样本集**（每条规则 1 个例子），不是**真实分布样本集**。
实际真实恶意分布里 prompt injection 占大头，而这里每类 rule 权重相同。

### 主要规则分组

- `BEHAV_*` — 运行时行为：`CRED_LEAK`, `COMMAND_EXEC`, `IMPORT_SUBPROCESS`
- `CQ_*` — 代码质量：`BROAD_EXCEPTION`, `INSECURE_RANDOM`, `SQL_INJECTION`, `DYNAMIC_EXEC`, `HARDCODED_SECRET`, `HIGH_ENTROPY_SECRET`, `PATH_TRAVERSAL`, `MALICIOUS_GUIDANCE`
- `LLM_*` — LLM 语义命中：`PROMPT_INJECTION`, `SOCIAL_ENGINEERING`, `OBFUSCATION`, `DATA_EXFILTRATION`, `MALICIOUS_GUIDANCE`, `SKILL_MD_MISMATCH`, `RESOURCE_ABUSE`, `UNDECLARED_TOOL_USE`, `PRIVILEGE_ESCALATION`, `DYNAMIC_CODE_EXEC`, `SQL_INJECTION`, `COMMAND_INJECTION`, `PATH_TRAVERSAL`, `HARDCODED_SECRET`, `SUPPLY_CHAIN_RISK`
- `SECRET_*` — 凭据泄漏：`JWT_TOKEN`, `OPENAI_KEY`, `DATABASE_URL`
- `PROMPT_INJECTION_*` — 提示注入：`IGNORE_INSTRUCTIONS`, `REVEAL_SYSTEM`, `BEHAVIOR_MANIPULATION`
- `SUPPLY_CHAIN_*` — 供应链：`GIT_HOOK_TAMPER`, `REMOTE_HEARTBEAT`
- `OBFUSCATION_*` / `SOCIAL_ENGINEERING_*` / `TI_*` 等其他类别

## 在 ASG 项目中的位置

- 副本 manifest：`tools/qax_manifest.csv`
- 旧 ground truth（**标签膨胀**版）：`tools/eval_ground_truth.json` 把 50 个全标 `1`
- 新 ground truth（3 类）：`tools/eval_ground_truth_3class.json`（待生成）
- 暂存目录：`C:/Windows/Temp/qax_staged/` — 50 个 zip 解出来的 skill 目录树
