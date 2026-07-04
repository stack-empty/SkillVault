#!/bin/bash
#
# Dynamic Skill Executor v1.0
# Executes skills in Docker sandbox with monitoring
#

set -e

SKILL_NAME="${1:-unknown}"
SKILL_PATH="${2:-}"
USER_PROMPT="${3:-Read the skill and execute it}"
REPO_ID="${4:-unknown}"
RISK_LEVEL="${5:-unknown}"
IN_PLACE_LOG="${6:-false}"

# Configuration
USE_NOVA="${USE_NOVA:-false}"  # 默认关闭：精简版 claude-skill-sandbox 不含 NOVA hooks。需要时 USE_NOVA=true 且用 NOVA_MODE=lite/full 重建镜像
NOVA_BLOCK="${NOVA_BLOCK:-false}"
TIMEOUT="${EXEC_TIMEOUT:-900}"

# Agent backend selector
# AGENT=claude (default)  → Claude CLI + ANTHROPIC_API_KEY
# AGENT=opencode          → OpenCode CLI + DEEPSEEK_API_KEY（用 DS V4-Pro 当大脑）
AGENT="${AGENT:-claude}"

# Get API key (按 backend 选 key)
if [ "$AGENT" = "opencode" ]; then
    if [ -n "$DEEPSEEK_API_KEY" ]; then
        API_KEY="$DEEPSEEK_API_KEY"
        AGENT_BASE_URL="${DEEPSEEK_BASE_URL:-https://api.deepseek.com/anthropic}"
        AGENT_MODEL="${DEEPSEEK_MODEL:-deepseek-v4-pro}"
        echo "[backend] OpenCode + DS V4-Pro (model=$AGENT_MODEL)"
    else
        echo "Error: AGENT=opencode 但 DEEPSEEK_API_KEY 没设"
        exit 1
    fi
elif [ -n "$ANTHROPIC_API_KEY" ]; then
    API_KEY="$ANTHROPIC_API_KEY"
    AGENT_BASE_URL="${ANTHROPIC_BASE_URL:-https://api.anthropic.com}"
    AGENT_MODEL="${CLAUDE_MODEL:-claude-opus-4-7}"
    echo "[backend] Claude CLI (model=$AGENT_MODEL)"
else
    echo "Error: AGENT=$AGENT 但 ANTHROPIC_API_KEY 没设"
    exit 1
fi

# Determine log directory
if [ "$IN_PLACE_LOG" = "true" ]; then
    TEST_DIR="${SKILL_PATH}/execution_records"
else
    TEST_DIR="${EXECUTION_LOGS_DIR}/${RISK_LEVEL}/${REPO_ID}/${SKILL_NAME}"
fi

mkdir -p "$TEST_DIR"

echo "=== Dynamic Skill Executor v1.0 ==="
echo "Skill: $SKILL_NAME"
echo "Repo: $REPO_ID"
echo "Risk: $RISK_LEVEL"
echo "Log Dir: $TEST_DIR"

# Get UID/GID for proper file permissions
HOST_UID=$(id -u)
HOST_GID=$(id -g)

# Generate unique container name — docker 只允许 [a-zA-Z0-9][a-zA-Z0-9_.-]
# 把 skill_name 里的空格 / 特殊字符替换成 -
SKILL_NAME_SAFE=$(echo "$SKILL_NAME" | tr -c 'a-zA-Z0-9._-' '-' | tr -s '-')
CONTAINER_NAME="skill-exec-${SKILL_NAME_SAFE}-${REPO_ID}-$$"

# Set mount arguments based on log mode
if [ "$IN_PLACE_LOG" = "true" ]; then
    SKILL_PARENT_DIR="$(dirname "$SKILL_PATH")"
    SKILL_BASENAME="$(basename "$SKILL_PATH")"
    TEST_DIR_MOUNT="/app/skill_parent/${SKILL_BASENAME}/execution_records"
    LOG_MOUNT_ARG=(-v "$SKILL_PARENT_DIR:/app/skill_parent")
else
    LOG_MOUNT_ARG=(-v "${EXECUTION_LOGS_DIR}:/app/logs")
    # 必须用挂载点根（/app/logs），不能用 /app/$TEST_DIR —— 后者是宿主机绝对路径，
    # 拼 /app/ 前缀后变成 /app/home/sh/.../execution_logs/...，跟挂载点完全错位，
    # strace.log/network.pcap 全部写到容器内虚拟路径，容器删除即丢失。
    TEST_DIR_MOUNT="/app/logs/${RISK_LEVEL}/${REPO_ID}/${SKILL_NAME}"
fi

# Run Docker container
# -u 0 覆盖 Dockerfile 里的 USER appuser，让容器以 root 启动；
# 后续脚本里再用 runuser 切到 appuser 跑 claude（蜜罐属主 = appuser）。
# 这样 strace 有 root 权限抓 syscall，claude 又以非特权用户跑。
docker run --rm \
    -u 0 \
    --name "$CONTAINER_NAME" \
    --cap-add=SYS_ADMIN \
    --cap-add=NET_ADMIN \
    --security-opt seccomp=unconfined \
    "${LOG_MOUNT_ARG[@]}" \
    -v asg-pip-cache:/home/appuser/.cache/pip:rw \
    -v "${PROJECT_ROOT}/executor/nova_setup.sh:/nova_setup.sh:ro" \
    -v "${PROJECT_ROOT}/executor/smart_monitor.py:/smart_monitor.py:ro" \
    -v "$SKILL_PATH:/skill_source:ro" \
    -w /tmp \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    -e ANTHROPIC_AUTH_TOKEN="$API_KEY" \
    -e ANTHROPIC_API_KEY="$API_KEY" \
    -e ANTHROPIC_BASE_URL="$AGENT_BASE_URL" \
    -e DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-$API_KEY}" \
    -e AGENT="$AGENT" \
    -e AGENT_MODEL="$AGENT_MODEL" \
    -e SKILL_NAME="$SKILL_NAME" \
    -e USER_PROMPT="$USER_PROMPT" \
    -e TEST_DIR="$TEST_DIR_MOUNT" \
    -e USE_NOVA="$USE_NOVA" \
    -e NOVA_BLOCK="$NOVA_BLOCK" \
    -e TIMEOUT="$TIMEOUT" \
    claude-skill-sandbox bash -c '

    # Setup user
    useradd -m -u "$HOST_UID" appuser 2>/dev/null
    groupmod -g "$HOST_GID" appuser 2>/dev/null
    mkdir -p "$TEST_DIR"
    chown appuser:appuser "$TEST_DIR"

    export HOME="/home/appuser"
    export APPUSER_HOME="/home/appuser"

    # Initialize NOVA
    if [ "$USE_NOVA" = "true" ]; then
        /nova_setup.sh "$APPUSER_HOME" "$([ "$NOVA_BLOCK" = "true" ] && echo "block" || echo "monitor")"
        export NOVA_REPORT_DIR="$TEST_DIR/nova"
        mkdir -p "$NOVA_REPORT_DIR"
        chown appuser:appuser "$NOVA_REPORT_DIR"
        echo "[NOVA] Initialized"
    fi

    # Copy skill
    mkdir -p "$APPUSER_HOME/.claude/"{skills,todos,cache,debug}
    # OpenCode 走 XDG 目录，一次建齐避免运行时 mkdir 失败
    mkdir -p "$APPUSER_HOME/.config/opencode" \
             "$APPUSER_HOME/.local/share/opencode" \
             "$APPUSER_HOME/.local/state/opencode" \
             "$APPUSER_HOME/.cache/opencode"
    echo "{\"hasCompletedOnboarding\": true}" > "$APPUSER_HOME/.claude.json"
    cp -r /skill_source "$APPUSER_HOME/.claude/skills/'"$SKILL_NAME"'"
    chown -R appuser:appuser "$APPUSER_HOME/.claude" "$APPUSER_HOME/.claude.json" "$APPUSER_HOME/.config" "$APPUSER_HOME/.local" "$APPUSER_HOME/.cache"

    # 为 Mode-3 Claude/OpenCode 准备 stub 目录 — 放在 $APPUSER_HOME 内避免 OpenCode auto-reject external_directory
    mkdir -p "$APPUSER_HOME/stub"
    ln -sfn "$APPUSER_HOME/stub" /stub 2>/dev/null || true
    python3 <<PYEOF_STUB
import os
os.makedirs("/home/appuser/stub", exist_ok=True)
os.environ.setdefault("STUB_DIR", "/home/appuser/stub")
pdf = (b"%PDF-1.4\n"
       b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
       b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
       b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
       b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
       b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n")
png = bytes.fromhex(
    "89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C489"
    "0000000D4944415478DA63FCCFC0F01F00050001FFA4F5DC450000000049454E44AE426082"
)
samples = {
    "/home/appuser/stub/sample.pdf": pdf,
    "/home/appuser/stub/sample.png": png,
    "/home/appuser/stub/sample.jpg": png,
    "/home/appuser/stub/sample.json": b"{\"key\":\"value\",\"items\":[1,2,3]}\n",
    "/home/appuser/stub/fields.json": b"{\"name\":\"Sample\",\"fields\":[]}\n",
    "/home/appuser/stub/config.json": b"{\"timeout\":10}\n",
    "/home/appuser/stub/sample.csv": b"col1,col2\nval1,val2\n",
    "/home/appuser/stub/sample.txt": b"Sample text\n",
    "/home/appuser/stub/sample.md": b"# Title\nSample\n",
    "/home/appuser/stub/sample.xml": b"<?xml version=\"1.0\"?><root/>\n",
    "/home/appuser/stub/sample.yml": b"key: value\n",
    "/home/appuser/stub/sample.html": b"<html><body><h1>x</h1></body></html>\n",
}
for p, b in samples.items():
    open(p, "wb").write(b)
print(f"[stub] created {len(samples)} files in /stub")
PYEOF_STUB
    chmod -R 755 /home/appuser/stub
    chown -R appuser:appuser /home/appuser/stub

    # 蜜罐凭据布置 — 用 heredoc 写 python 脚本到文件，避开外层 bash 单引号冲突
    if [ -n "${CANARY_FILES_B64:-}" ]; then
        echo "$CANARY_FILES_B64" | base64 -d > /tmp/canary_data.json
        cat > /tmp/canary_setup.py <<"CANARY_PYEOF"
import json
from pathlib import Path
data = json.load(open("/tmp/canary_data.json"))
HOME = "/home/appuser"
for rel_path, content in data.items():
    p = Path(HOME) / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    if "id_rsa" in p.name or "credentials" in str(p):
        p.chmod(0o600)
    else:
        p.chmod(0o644)
print("[canary] planted " + str(len(data)) + " honeypot files")
CANARY_PYEOF
        python3 /tmp/canary_setup.py 2>&1 || echo "[canary] setup failed"
        chown -R appuser:appuser /home/appuser/.ssh /home/appuser/.aws 2>/dev/null || true
        chown appuser:appuser /home/appuser/.env 2>/dev/null || true
    fi

    cd "$APPUSER_HOME"

    # Start tcpdump
    echo "[Monitor] Starting tcpdump..."
    tcpdump -i any -w "$TEST_DIR/network.pcap" -s 0 2>/dev/null &
    TCPDUMP_PID=$!

    # ============================================================
    # Tier-1 监控增强（MalSkillBench arXiv:2606.07131 同款）
    # ============================================================
    # 1. inotifywait 高危目录写入：实时捕捉 .ssh/authorized_keys 写入、
    #    crontab/systemd 持久化、shell rc 注入等
    echo "[Monitor] Starting inotify watcher on high-risk paths..."
    # 预先建出待 watch 的目录（不存在的 inotifywait 会跳过）
    mkdir -p "$APPUSER_HOME/.ssh" "$APPUSER_HOME/.aws" \
             "$APPUSER_HOME/.config/systemd" 2>/dev/null
    chown -R appuser:appuser "$APPUSER_HOME/.ssh" "$APPUSER_HOME/.aws" \
             "$APPUSER_HOME/.config/systemd" 2>/dev/null
    INOTIFY_WATCH_DIRS=(
        "$APPUSER_HOME/.ssh"
        "$APPUSER_HOME/.aws"
        "$APPUSER_HOME/.config/systemd"
    )
    # 系统级高危位（如果存在）
    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly \
             /etc/systemd/system /etc/sudoers.d; do
        [ -d "$d" ] && INOTIFY_WATCH_DIRS+=("$d")
    done
    # 单独 watch 几个高危文件（不能 watch 不存在的文件 → touch 出来）
    for f in "$APPUSER_HOME/.bashrc" "$APPUSER_HOME/.profile" \
             "$APPUSER_HOME/.bash_profile"; do
        [ -f "$f" ] || touch "$f" 2>/dev/null
        chown appuser:appuser "$f" 2>/dev/null
        INOTIFY_WATCH_DIRS+=("$f")
    done
    # 加 access + open：让 canary 凭据文件被"读"的动作也被抓
    # （之前只 watch 写事件，导致所有跑过的 skill canary 触发率 0）
    inotifywait -m -r -e create,modify,delete,attrib,move,close_write,access,open \
        --format "%T %w%f %e" --timefmt "%s" \
        "${INOTIFY_WATCH_DIRS[@]}" \
        > "$TEST_DIR/inotify.log" 2> "$TEST_DIR/inotify.err" &
    INOTIFY_PID=$!

    # File system snapshot
    echo "[Monitor] Creating baseline snapshot..."
    python3 /smart_monitor.py snapshot /tmp/fs_state.json "$APPUSER_HOME"
    # ============================================================
    # Pre-Execute v3 — 强制执行版（写到独立 sh，让 strace bash 内 source）
    # ============================================================
    # 之前简化版让 agent 自己 bash run，但 DS safety 训练让它看到明显恶意
    # 代码就拒绝执行，只静态读源码 → strace 永远抓不到真 IOC
    # 现在把 pre-exec 写到 /tmp/pre_exec.sh，让后面 strace 包裹的 bash -c
    # 在跑 agent 前先 source 这个 sh，所有 python3 execve 都被 strace 捕获
    PRE_EXEC_DIR="$TEST_DIR/pre_exec"
    mkdir -p "$PRE_EXEC_DIR"
    PRE_EXEC_SH="/tmp/pre_exec.sh"
    PRE_EXEC_SUMMARY="$APPUSER_HOME/pre_exec_evidence.txt"
    # 生成 pre_exec.sh —— 内容会在 strace 包裹的 bash 内执行
    # pre-exec 命令将内联进 strace bash -c（避免 heredoc + docker exec 双重 quoting bug）
    # 预先写空 summary，agent 即使 pre-exec 失败也能 cat 到东西
    echo "Pre-Execute v3 待 strace 内执行后填写。" > "$PRE_EXEC_SUMMARY"
    chown appuser:appuser "$PRE_EXEC_SUMMARY" 2>/dev/null || true

    # Execute skill
    echo ""
    echo "=========================================="
    echo "Executing Skill (timeout: '${TIMEOUT}s')"
    echo "=========================================="

    STRACE_LOG="$TEST_DIR/strace.log"
    # -v 让 strace 打印完整 envp（execve 调用的环境变量数组），
    # 用于事后扫描 AWS_SECRET_*/ANTHROPIC_API_KEY 等凭据是否被传给子进程
    # （Credential Leakage paper arXiv:2604.03070 的 #1 检测点）。
    STRACE_OPTS="-f -v -s 2000 -e trace=open,openat,creat,write,unlink,rename,mkdir,rmdir,execve,connect,accept,sendto,recvfrom"

    # 用 runuser 切到 appuser — su 在容器里要 root 密码会死锁，runuser 无需密码
    # 强制 claude-opus-4-7（4.8 贵 30%，4.7 对沙箱执行已经够用）
    # 用 tee（非 -a）覆盖旧 claude_output.txt，避免多次跑追加导致中英文混杂
    # 注意：strace 续行符 \ 后面**不能跟注释**，否则 bash 把后续行当独立命令，
    # strace 拿不到 PROG → "must have PROG [ARGS]" 报错（曾经踩过的坑）
    # Backend agent 命令 — Claude / OpenCode 切换
    if [ "$AGENT" = "opencode" ]; then
        # OpenCode + DS：DS 是 OpenCode 原生 provider，要 DEEPSEEK_API_KEY 环境变量
        # opencode run 输出走 stdout，不需要 --print
        AGENT_CMD="opencode run --model deepseek/${AGENT_MODEL}"
        echo "[exec] AGENT=opencode model=deepseek/$AGENT_MODEL"
    else
        # Claude（默认）
        AGENT_CMD="claude --dangerously-skip-permissions --print --model ${AGENT_MODEL:-claude-opus-4-7}"
        echo "[exec] AGENT=claude model=${AGENT_MODEL:-claude-opus-4-7}"
    fi

    # Pre-Execute v3 — 内嵌到 strace bash -c "..." 双引号里
    # 外层 docker bash -c 用单引号，所以这里不能再有任何单引号字符
    strace $STRACE_OPTS -o "$STRACE_LOG" runuser -u appuser -- env HOME=$APPUSER_HOME DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-}" ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" ANTHROPIC_AUTH_TOKEN="${ANTHROPIC_AUTH_TOKEN:-}" ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL:-}" bash -c "cd $APPUSER_HOME && { for py in \$(find /home/appuser/.claude/skills -name *.py -type f 2>/dev/null); do echo \"=== \$py ===\"; timeout 8 python3 \"\$py\" 2>&1 | head -15; SSH_PRIVATE_KEY=CK AWS_ACCESS_KEY_ID=CK ANTHROPIC_API_KEY=CK timeout 8 python3 \"\$py\" 2>&1 | head -15; done > /home/appuser/pre_exec_evidence.txt 2>&1; }; echo \"${USER_PROMPT}\" | stdbuf -oL timeout ${TIMEOUT}s ${AGENT_CMD}" 2>&1 | tee "$TEST_DIR/claude_output.txt"

    EXIT_CODE=${PIPESTATUS[0]}

    echo ""
    if [ $EXIT_CODE -eq 124 ]; then
        echo "Warning: Execution timeout (${TIMEOUT}s)"
    else
        echo "Execution complete (exit code: $EXIT_CODE)"
    fi

    kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null

    # 关 inotify
    kill $INOTIFY_PID 2>/dev/null
    wait $INOTIFY_PID 2>/dev/null
    # 简单分类一下 inotify 命中（标记敏感目录的事件方便事后筛）
    if [ -s "$TEST_DIR/inotify.log" ]; then
        echo "[Monitor] inotify captured $(wc -l < "$TEST_DIR/inotify.log") events"
    fi

    # Collect NOVA reports
    if [ "$USE_NOVA" = "true" ]; then
        echo "[NOVA] Collecting reports..."
        NOVA_SRC="/home/appuser/.nova-protector/reports"
        NOVA_DEST="$TEST_DIR/nova"

        for i in {1..15}; do
            if [ -d "$NOVA_SRC" ] && [ "$(ls -A $NOVA_SRC 2>/dev/null)" ]; then
                cp -r "$NOVA_SRC"/. "$NOVA_DEST/" 2>/dev/null
                echo "[NOVA] Reports collected"
                break
            fi
            sleep 2
        done
    fi

    # File system diff
    echo "[Monitor] Analyzing file changes..."
    python3 /smart_monitor.py diff /tmp/fs_state.json "$APPUSER_HOME" "$TEST_DIR"

    echo "=========================================="
    echo "Execution Complete"
    echo "=========================================="
'

echo ""
echo "Done: $TEST_DIR"
