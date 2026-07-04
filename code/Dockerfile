# Claude Skill Sandbox 镜像
# 用于模式二/三在隔离容器里动态执行 skill 脚本。
#
# 构建：
#   docker build -t claude-skill-sandbox code/
#
# 镜像内含：python3 + bash + strace + tcpdump + Node.js 18 + Claude Code CLI
# + 38 个常用 Python 库（让 skill 脚本不会一上来就 ImportError）
#
# 蜜罐假凭证、runner 脚本均由宿主机在运行时挂载/写入，不烤进镜像。

# 完整版 python:3.11（非 slim），自带 gcc/make/python-dev，避免 pandas/lxml
# 这类带 C 扩展的包预编译 wheel 找不到时回退到源码编译失败。
# 选 3.11 是因为很多新 skill 的依赖（如 networkx>=3.6 / mcp）要求 Python>=3.11。
FROM python:3.11

# 国内 APT 源（USTC），加速 strace/tcpdump 等系统包下载
RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf 'Types: deb\nURIs: https://mirrors.ustc.edu.cn/debian\nSuites: bookworm bookworm-updates\nComponents: main contrib non-free non-free-firmware\n\nTypes: deb\nURIs: https://mirrors.ustc.edu.cn/debian-security\nSuites: bookworm-security\nComponents: main contrib non-free non-free-firmware\n' \
    > /etc/apt/sources.list.d/debian.sources || true

# 系统依赖：strace/tcpdump/inotify-tools 是动态证据采集的核心
# inotify-tools 用于实时监控高危目录（~/.ssh / /etc/cron.d / systemd unit dir）
# 是否被写入（MalSkillBench arXiv:2606.07131 论文同款方案）。
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        strace tcpdump inotify-tools curl wget git sudo file procps \
        iputils-ping net-tools jq ca-certificates \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Node.js 18（模式三需要）
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Claude Code CLI（模式三，默认 backend）
RUN npm install -g @anthropic-ai/claude-code || \
    echo "warn: claude-code 安装失败（仅影响模式三 / Claude backend）"

# OpenCode CLI（模式三可选 backend，支持 DS / GPT / Gemini / Ollama 等）
# 通过 npm 装最稳，sst/opencode v1.17+ 发布到 npm 名 'opencode-ai'
# 装失败不影响 Claude backend
RUN npm install -g opencode-ai || \
    echo "warn: opencode 安装失败（仅影响 OpenCode backend）"

# 国内 pip 源（清华），避免 numpy/pandas 这种 50MB+ 的包从 pypi.org 下到一半断
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple/ && \
    pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn && \
    pip install --upgrade pip

# ============================================================
# Python 库分批安装：每批一个 RUN 层
# 好处：(1) 某批失败立刻定位是哪批 (2) Docker 层缓存，重建从失败那层起
#       (3) 可选包用 || true 兜底，单包失败不破坏整体构建
# ============================================================

# 第 1 批：HTTP 网络（必有 wheel，秒装）
RUN pip install \
    requests httpx aiohttp websockets urllib3

# 第 2 批：数据格式与解析（必有 wheel）
RUN pip install \
    pyyaml toml jsonschema markdown markdownify python-dotenv chardet

# 第 3 批：CLI / 模板 / 输出美化（必有 wheel）
RUN pip install \
    click typer rich jinja2 pydantic python-dateutil

# 第 4 批：LLM SDK（轻量）
RUN pip install \
    openai anthropic tiktoken

# 第 5 批：数据科学（重量级 - 有 C 扩展。完整 python 镜像下应该用 wheel）
RUN pip install \
    numpy pandas

# 第 6 批：数据库客户端（可选，失败不破坏）
RUN pip install \
    sqlalchemy psycopg2-binary pymysql redis pymongo \
    || echo "warn: 部分数据库客户端装失败（影响有限）"

# 第 7 批：文件处理（可选，pdfplumber/lxml 比较重）
RUN pip install \
    pathspec watchdog tenacity beautifulsoup4 lxml \
    || echo "warn: 部分文件库装失败"

# 第 8 批：文档（pdf/docx/xlsx，可选）
RUN pip install \
    pdfplumber python-docx openpyxl \
    || echo "warn: 部分文档库装失败"

# 第 9 批：网络/SSH 客户端 + 加密
RUN pip install \
    paramiko cryptography \
    || echo "warn: paramiko/cryptography 装失败"

# 第 10 批：AI agent/skill 生态常用（networkx 用于知识图谱，mcp 是 Anthropic Model Context Protocol SDK）
RUN pip install \
    networkx mcp \
    || echo "warn: networkx/mcp 装失败"

WORKDIR /app

# 非 root 用户（uid 1000，与宿主机挂载的假 HOME 属主对齐）
RUN useradd -m -u 1000 -s /bin/bash appuser && \
    mkdir -p /app/logs /home/codexsafe/.cache/pip && \
    chown -R appuser:appuser /app /home/codexsafe

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER appuser
CMD ["/bin/bash"]
