# SkillVault · 分层多级防护架构的大模型 Skill 安全检测系统

面向 Claude Code / OpenCode / Gemini CLI 等 AI 编码 Agent 生态中传播的第三方 `SKILL.md` 包，实现"**声明—实现—运行行为**"三域一致性验证的多层安全审计系统。

参考文献：**MalSkillBench: A Runtime-Verified Benchmark of Malicious Agent Skills** (arXiv:2606.07131)

---

## 一、核心创新

| # | 创新点 | 说明 |
|---|---|---|
| 1 | **三域一致性验证** | 声明（SKILL.md）、实现（脚本+资源）、运行行为（syscall/网络）交叉核验 |
| 2 | **5 阶段分层流水线** | Stage 0 静态 IOC → Stage 1 DS 语义 → Stage 2A Claude API → Stage 2B OpenCode Docker → Stage 3 Claude CLI Docker |
| 3 | **VM 内 Docker 动态取证** | strace/tcpdump/inotify + Canary 蜜罐凭据，产生系统调用级铁证 |
| 4 | **多模态隐藏指令恢复** | OCR / 二维码 / EXIF / LSB / 附加片段跨媒体重建 |
| 5 | **多源证据融合** | 6 路证据加权 + 高置信下限（Claude 自报 MAL / Canary 泄露 / Runtime IOC≥5）|
| 6 | **DS_CONF_GATE 门控节流** | DS conf ≥ 0.95 早退，成本节省 90%+ |

## 二、目录结构

```
skillvault/
├── asg/                 核心检测引擎（rules.py, ssd_runner.py, risk_scorer.py, vm_ssh.py）
├── web_ui/              Flask 网页前端 + 三种查看模式
├── code/                Docker 沙箱执行器（run_skill.sh, Dockerfile）
├── tools/               批量评测与实用工具（malskillbench_runner.py, unified_15.py 等）
├── docs/                中英文说明 + 静态化的扫描结果页
├── examples/            示例 Skill
├── analysis_results/    演示扫描结果
└── requirements.txt
```

## 三、快速开始

### 3.1 环境准备

```bash
# Python 3.12
pip install -r requirements.txt

# 环境变量（填自己的 key）
export DEEPSEEK_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-...
export ANTHROPIC_BASE_URL=https://api.anthropic.com  # 或代理

# 如果要动态执行：Docker + Ubuntu VM
# 复制 asg/vm_config.example.json → asg/vm_config.json 并填参数
```

### 3.2 单样本扫描

```bash
# 静态 + SSD 4 维度语义研判
python -m asg.asg_cli scan path/to/skill/ --enable-honeypot --enable-ssd

# 加 Claude API 跨模型复检
python -m asg.asg_cli scan path/to/skill/ --enable-ssd --enable-claude

# VM Docker 动态执行（strace/tcpdump/canary）
python -m asg.asg_cli vm-ssh-run path/to/skill/ --enable-honeypot

# §3.3 模式（不依赖 Claude API，只用 DS）
python -m asg.asg_cli vm-paper-run path/to/skill/ --enable-honeypot
```

### 3.3 Web UI

```bash
python web_ui/app.py
# → http://127.0.0.1:8765/
```

**三种查看模式**：
- `/results` — 所有已扫描 skill 卡片列表
- `/report/<skill_name>` — 单样本完整报告（5 阶段 + 六路证据融合）
- `/asg` — ASG 全景 dashboard

## 四、5 阶段流水线

```
Stage 0  静态 IOC 挖掘         全跑        0.5s    ¥0
     ↓
Stage 1  DeepSeek V4-Pro 语义   全跑        5s      ¥0.001
     ↓ conf<0.95 才升级
Stage 2A Claude API 跨模型复检  ~13%        10s     ¥0.05
     ↓
Stage 2B OpenCode+DS Docker    ~17%        60-90s  ¥0.05
         + strace/tcpdump/canary
     ↓ 每 10 抽 1
Stage 3  Claude CLI Docker     ~10%        30s     ¥1.2
         + agent-in-the-loop
     ↓
六路证据融合 → composite_risk (verdict, risk_score 0-100)
```

## 五、3D 攻击分类学

**|C| = 9×4 (CI) + 15×3 (PI) + 9×3 (MIXED) = 108 攻击单元**

- **Attack Vector (3)**：CI (Code Injection) · PI (Prompt Injection) · MIXED
- **Behavior (15)**：
  - B1-B9 三域通用：Data Exfil / Cred Theft / RCE / Malware Delivery / Persistence / Reverse Shell / Ransom / Resource Abuse / Priv Esc
  - B10-B15 PI-only（agent 控制面）：Role Hijack / Safety Bypass / Instruction Override / Sys Prompt Leak / Goal Hijacking / Content Manipulation
- **Insertion Strategy**：CI 4 种 + PI 3 种 + MIXED 3 种

## 六、验证结果（受控样本）

| 集合 | 规模 | 一致率 |
|---|---|---|
| MalSkillBench 30-batch | 30 | **83.3%**（25/30）|
| unified_15 固定集合 | 15 | **87%**（13/15）|
| unified_5_more 高争议 | 5 | 60%（3/5）|
| SkillCamo 多模态对抗 | 56 | **100%**（32/32 攻击命中，0/24 良性误报）|
| Multimodal-Mix | 15 | **100%**（11/11 攻击命中）|

## 七、技术栈

- Python 3.12 · asyncio · concurrent.futures
- **DeepSeek V4-Pro** 语义研判（中文推理）
- **Anthropic Claude Sonnet** 跨模型复检
- **OpenCode CLI** Agent-in-the-Loop（§3.3 复现）
- **Docker 24** 气隙沙箱 · `--network none` + `cap-drop=ALL`
- `strace -f` · `inotifywait -m -e access,open,create` · `tcpdump`
- `paramiko 3.x` SSH → Ubuntu VM
- Flask 3.x + Jinja2 · 纯 CSS Grid / Flexbox · SVG 内联流程图

## 八、安全边界

- **公开服务模式**（`ASG_PUBLIC_MODE=1`）只开放静态 + 语义路径，动态执行接口关闭
- **动态执行**必须在授权部署环境中的**专用 VM + Docker 双层隔离**里进行
- **Canary 蜜罐凭据**（`.env`/`.ssh/id_rsa`/`.aws/credentials`）全部是带唯一标记的假凭据，真凭据不进容器
- **DNS sinkhole** 全部指向 `198.18.0.x`（RFC 5735 保留段），TCP 挂起保留证据

## 九、团队介绍

本小队专注大模型技能安全的科创小队，依托多层级分层检测架构，实现 AgentSkill 全链路风险识别。成员精通网络攻防、LLM 算法与系统开发，协同完成分层检测系统研发，致力补齐 AI 智能体 skill 安全防护短板。

## 十、许可与致谢

- 数据集参考：**MalSkillBench** (arXiv:2606.07131) · 论文开源 repo: [lxyeternal/MalSkillBench](https://github.com/lxyeternal/MalSkillBench)
- 静态规则参考：Cisco Skill Scanner · Sentry Skill Scanner · Tencent AI-Infra-Guard · Snyk Agent Scan
- 提示注入研究：Greshake et al. (indirect PI) · Bagdasaryan et al. (multi-modal II)

作品面向第十九届全国大学生信息安全竞赛（作品赛）暨第三届"长城杯"网数智安全大赛提交。
