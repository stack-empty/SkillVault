"""AST-based detection for Python source files.

Complement to the regex engine in `asg/rules.py`. Targets the evasion classes
that regex fundamentally cannot handle:
  - identifier reconstruction: 'metsys'[::-1] / bytes.fromhex('6f73').decode()
  - indirection chains: getattr(getattr(__builtins__, '__im'+'port__'), ...)
  - dormant payloads: dangerous call gated by time.time() / gethostname()
  - exception-path hiding: except: __import__('os').system(...)
  - decorator-time exec: @decorator that performs side effects at import-time
  - serialization sinks: marshal/pickle/yaml.load → exec
  - native libraries: ctypes.CDLL (AST cannot audit .so contents)
  - subclasses jailbreak: ().__class__.__mro__[-1].__subclasses__()
  - DNS-style exfil: socket.gethostbyname(encoded_secret + '.attacker')

Each AST finding reuses the existing `Finding` dataclass from `asg.rules` and
the existing rule_ids (SC1/SC2/SC3/E1/E2), so downstream scoring/UI work
without modification. `pattern` is set to "<ast>" so the report can
distinguish AST-source findings from regex-source ones.
"""

from __future__ import annotations

import ast
import base64
import re
from pathlib import Path

from asg.rules import EVIDENCE_TYPES, Finding


# ---------------------------------------------------------------------------
# Sink catalogs. Qualified names are post-resolution (after import-alias and
# getattr-string folding). Keep these CONSERVATIVE: false positives kill
# scanner credibility faster than missed advanced attacks.
# ---------------------------------------------------------------------------

# 已知合法 CLI 工具：subprocess.run(['<这些>', ...]) 是常规外部工具调用，
# 不构成 shell injection 风险。命中时把 SC1 从 HIGH 降到 LOW（仍记录为
# capability，给 risk_scorer 留判断空间），避免 docx/pptx/screenshot 这种
# 用 libreoffice/pandoc/headless browser 的合法 skill 被当 HIGH 报。
KNOWN_DOC_AND_TOOL_BINARIES: set[str] = {
    # 文档转换
    "libreoffice", "soffice", "pandoc", "wkhtmltopdf",
    "tesseract", "convert", "magick", "imagemagick",
    "ghostscript", "gs", "pdftk", "pdftotext", "qpdf",
    # 浏览器自动化
    "chromedriver", "geckodriver", "chromium", "chrome",
    "playwright", "puppeteer", "headless-chrome",
    # 媒体
    "ffmpeg", "ffprobe", "sox", "exiftool",
    # 版本控制 / 包管理（只读 / 常规操作）
    "git", "hg", "svn",
    "npm", "yarn", "pnpm", "pip", "uv", "poetry",
    # 系统查询（只读）
    "ls", "cat", "head", "tail", "wc", "stat", "file",
    "which", "whereis", "uname", "hostname",
    # 截图 / 屏幕（含 macOS / Linux 各种工具）
    "screencapture", "scrot", "import", "gnome-screenshot",
    "spectacle", "flameshot", "maim", "shutter",
    "osascript",  # macOS AppleScript — 截图/UI 自动化常用
    "xdotool",    # Linux X11 自动化
    "xset", "xrandr", "wmctrl",  # X11 工具
    # 数据处理
    "jq", "yq", "csvkit", "csvq",
}


def _subprocess_arg0(call_node: ast.Call) -> str | None:
    """提取 subprocess.run(['cmd', ...]) 的 'cmd'，或 subprocess.run('cmd ...') 的首词。

    覆盖常见 form:
        subprocess.run(['cmd', 'arg1', ...])     ← 直接 list
        subprocess.run(['cmd'] + extra_args)     ← list + variable (常见 wrapper)
        subprocess.run(['cmd', *extra_args])     ← starred unpack
        subprocess.run('cmd --arg ...')           ← shell-style string
    运行时拼装的命令照常按 HIGH 报（保持安全态）。
    """
    if not call_node.args:
        return None
    arg = call_node.args[0]

    # ['tool'] + variable / ['tool'] + ['arg', ...] (BinOp(Add))
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        # 找最左操作数作为 list 来源
        left = arg.left
        if isinstance(left, ast.List) and left.elts:
            arg = left  # 退化成 list 处理
    # subprocess.run(['libreoffice', '--convert-to', ...])
    if isinstance(arg, ast.List) and arg.elts:
        first = arg.elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value.split("/")[-1].lower()
        # ['*known_list_var'] — 无法判定，落空
        return None
    # subprocess.run('libreoffice --convert-to ...')
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        tokens = arg.value.strip().split()
        if tokens:
            return tokens[0].split("/")[-1].lower()
    return None


SHELL_SINKS: set[str] = {
    "os.system", "os.popen", "os.execv", "os.execve", "os.execvp",
    "os.execvpe", "os.spawnl", "os.spawnv", "os.spawnvp",
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    "commands.getoutput", "commands.getstatusoutput",
    "pty.spawn",
}

DYNAMIC_EXEC_SINKS: set[str] = {
    "exec", "eval", "compile",
    "__import__", "builtins.__import__",
    "importlib.import_module", "importlib.__import__",
    "runpy.run_module", "runpy.run_path", "runpy._run_code",
}

SERIALIZATION_SINKS: dict[str, str] = {
    "pickle.loads": "HIGH",
    "pickle.load": "HIGH",
    "cPickle.loads": "HIGH",
    "cPickle.load": "HIGH",
    "marshal.loads": "HIGH",
    "marshal.load": "HIGH",
    "dill.loads": "HIGH",
    "dill.load": "HIGH",
    "yaml.load": "MEDIUM",         # only without explicit safe Loader (we don't introspect args yet)
    "yaml.unsafe_load": "HIGH",
    "shelve.open": "MEDIUM",
}

NATIVE_LIB_SINKS: set[str] = {
    "ctypes.CDLL", "ctypes.WinDLL", "ctypes.OleDLL", "ctypes.PyDLL",
    "ctypes.cdll.LoadLibrary", "ctypes.windll.LoadLibrary",
}

CODE_OBJECT_BUILDERS: set[str] = {
    "types.FunctionType", "types.CodeType", "types.MethodType",
}

FRAME_ESCAPE_SINKS: set[str] = {
    "sys._getframe", "inspect.currentframe", "inspect.stack",
}

NETWORK_EXFIL_SINKS: set[str] = {
    "requests.post", "requests.put", "requests.patch", "requests.delete",
    "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
    "aiohttp.ClientSession.post", "aiohttp.ClientSession.put",
    "urllib.request.urlopen", "urllib.request.Request",
    "urllib3.PoolManager.request",
    "smtplib.SMTP", "smtplib.SMTP_SSL", "smtplib.LMTP",
    "ftplib.FTP", "ftplib.FTP_TLS",
    # DNS-only sinks — used by DNS-tunnel exfil. Net detection is fine here:
    # legitimate code rarely encodes a secret into the hostname.
    "socket.gethostbyname", "socket.gethostbyname_ex",
    "dns.resolver.resolve", "dnspython.resolver.resolve",
}

DORMANCY_GUARDS: dict[str, str] = {
    "time.time": "time gate",
    "time.monotonic": "time gate",
    "datetime.datetime.now": "time gate",
    "datetime.datetime.utcnow": "time gate",
    "datetime.now": "time gate",
    "datetime.utcnow": "time gate",
    "socket.gethostname": "host fingerprint gate",
    "platform.node": "host fingerprint gate",
    "platform.system": "platform fingerprint gate",
    "os.uname": "host fingerprint gate",
    "getpass.getuser": "user fingerprint gate",
}

# Constant-decoding helpers we'll evaluate inside _const_str.
TAINT_SOURCES: dict[str, str] = {
    "base64.b64decode": "base64 decode",
    "base64.b32decode": "base32 decode",
    "base64.b16decode": "base16 decode",
    "base64.a85decode": "ascii85 decode",
    "codecs.decode": "codecs.decode (e.g. rot13/hex)",
    "marshal.loads": "marshal code object",
    "marshal.load": "marshal code object",
    "pickle.loads": "pickle object",
    "pickle.load": "pickle object",
    "zlib.decompress": "zlib decompress",
    "gzip.decompress": "gzip decompress",
    "bz2.decompress": "bz2 decompress",
    "lzma.decompress": "lzma decompress",
    "binascii.unhexlify": "hex decode",
    "bytes.fromhex": "hex decode",
}

SENSITIVE_ENV_PATTERN = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API[_-]?KEY|"
    r"AWS_|GCP_|AZURE_|GITHUB_|GITLAB_|"
    r"ANTHROPIC_|OPENAI_|DEEPSEEK_|STRIPE_|TWILIO_|"
    r"SLACK_|DISCORD_|TELEGRAM_|"
    r"SSH_|SMTP_|DB_|DATABASE_URL|MONGODB|REDIS_)",
    re.IGNORECASE,
)

# Reading these env vars is overwhelmingly benign; suppress E2 noise.
SAFE_ENV_WHITELIST: set[str] = {
    "PATH", "HOME", "USER", "USERNAME", "LOGNAME", "PWD",
    "SHELL", "TERM", "TZ", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
    "DISPLAY", "WAYLAND_DISPLAY",
    "TMPDIR", "TEMP", "TMP",
    "PYTHONPATH", "PYTHONHOME", "PYTHONUNBUFFERED",
    "PYTHONDONTWRITEBYTECODE", "PYTHONIOENCODING",
    "VIRTUAL_ENV", "CONDA_PREFIX", "CONDA_DEFAULT_ENV",
    "EDITOR", "VISUAL", "PAGER",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR",
}


def _try_int(node: ast.AST | None) -> int | None:
    """Fold an int constant, including the AST form `-1` = UnaryOp(USub, Constant(1))."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) \
            and isinstance(node.operand, ast.Constant) \
            and isinstance(node.operand.value, int):
        return -node.operand.value
    return None


# ---------------------------------------------------------------------------
# Name resolution: turn AST refs into qualified dotted names.
# ---------------------------------------------------------------------------

class _Resolver:
    """Track import aliases + simple const-string vars, then resolve qualified
    names for Call / Attribute / Subscript expressions.

    Intentionally limited — no full constant propagation, no flow analysis.
    Good enough to catch the common evasion patterns documented in the
    test suite while keeping false-positive risk low.
    """

    def __init__(self) -> None:
        # alias -> module dotted name. e.g. "os" → "os", "subp" → "subprocess"
        self.module_alias: dict[str, str] = {}
        # alias -> "module.attr". e.g. {"run": "subprocess.run"} after
        # `from subprocess import run`
        self.name_alias: dict[str, str] = {}
        # var_name -> constant str value, captured from `x = "literal"` assigns.
        self.const_vars: dict[str, str] = {}

    # --- recording ---------------------------------------------------------
    def record_import(self, node: ast.Import | ast.ImportFrom) -> None:
        if isinstance(node, ast.Import):
            for a in node.names:
                self.module_alias[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for a in node.names:
                local = a.asname or a.name
                self.name_alias[local] = f"{mod}.{a.name}" if mod else a.name

    def record_assign(self, node: ast.Assign) -> None:
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return
        val = self.const_str(node.value)
        if val is not None:
            self.const_vars[node.targets[0].id] = val

    # --- resolution --------------------------------------------------------
    def resolve_call_target(self, node: ast.AST) -> str | None:
        """Resolve a callable expression to its qualified name. Best-effort.

        Handles:
            os.system                            -> "os.system"
            system  (after from os import system)-> "os.system"
            subp.run (after import subprocess as subp) -> "subprocess.run"
            getattr(os, "sys"+"tem")             -> "os.system"
            getattr(__import__("os"), "system")  -> "os.system"
            __import__("os").system              -> "os.system"
        """
        # Direct attribute
        if isinstance(node, ast.Attribute):
            base = self.resolve_module_ref(node.value)
            if base:
                return f"{base}.{node.attr}"
        # Bare name (builtin or from-import alias)
        if isinstance(node, ast.Name):
            return self.name_alias.get(node.id, node.id)
        # getattr(obj, "attr")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "getattr" and len(node.args) >= 2:
            obj = self.resolve_module_ref(node.args[0])
            attr = self.const_str(node.args[1])
            if obj and attr:
                return f"{obj}.{attr}"
        return None

    def resolve_module_ref(self, node: ast.AST) -> str | None:
        """Resolve something that should be a module / object reference."""
        if isinstance(node, ast.Name):
            return self.module_alias.get(
                node.id, self.name_alias.get(node.id, node.id)
            )
        if isinstance(node, ast.Attribute):
            base = self.resolve_module_ref(node.value)
            return f"{base}.{node.attr}" if base else None
        # 任何 call(...) → 如果 call 解出来是 import-like，把 arg0 当模块名。
        # 覆盖直接 __import__('os')、import_module('os')、以及 getattr 取出来
        # 再调用的间接形式：getattr(__builtins__, '__import__')('os')。
        if isinstance(node, ast.Call):
            t = self.resolve_call_target(node.func)
            if t in {
                "__import__", "builtins.__import__",
                "importlib.import_module", "importlib.__import__",
            }:
                if node.args:
                    name = self.const_str(node.args[0])
                    if name:
                        return name
            # 间接 import：getattr 链拼出 __import__ 或 __import__.__call__
            # 这种 path 在正常代码里几乎不会出现，命中即高度可疑。
            if t and (t.endswith(".__import__")
                      or t.endswith(".__import__.__call__")):
                if node.args:
                    name = self.const_str(node.args[0])
                    if name:
                        return name
            # getattr(<obj>, "<attr>") 当 module ref：也直接走 resolve_call_target
            # 拿全名（如 "os.environ" / "os.path" 这类）。
            if isinstance(node.func, ast.Name) and node.func.id == "getattr" \
                    and len(node.args) >= 2:
                return self.resolve_call_target(node)
        return None

    def const_str(self, node: ast.AST) -> str | None:
        """Aggressive constant-string folding: literals, concat, reverse slice,
        bytes.fromhex(...).decode(), base64.b*decode(literal).decode(),
        bytes(literal_int_list).decode(), and recorded const vars."""
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return node.value
            if isinstance(node.value, bytes):
                try:
                    return node.value.decode("utf-8")
                except UnicodeDecodeError:
                    return None
        if isinstance(node, ast.Name) and node.id in self.const_vars:
            return self.const_vars[node.id]
        # "a" + "b"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            l = self.const_str(node.left)
            r = self.const_str(node.right)
            if l is not None and r is not None:
                return l + r
        # f-string with only constant parts
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for v in node.values:
                p = self.const_str(v)
                if p is None:
                    return None
                parts.append(p)
            return "".join(parts)
        if isinstance(node, ast.FormattedValue):
            return self.const_str(node.value)
        # "abc"[::-1]   (Python AST 把 -1 表示成 UnaryOp(USub, Constant(1))，
        # 也有可能是 Constant(-1)，两种都要识别)
        if isinstance(node, ast.Subscript):
            base = self.const_str(node.value)
            if base is not None and isinstance(node.slice, ast.Slice):
                step = node.slice.step
                step_val = _try_int(step)
                if step_val == -1:
                    return base[::-1]
                # 完整 slice 支持：base[start:stop:step]
                if step is None or step_val is not None:
                    lo = _try_int(node.slice.lower)
                    hi = _try_int(node.slice.upper)
                    try:
                        return base[lo:hi:step_val]
                    except Exception:
                        return None
        # bytes.fromhex("6f73").decode()  OR  binascii.unhexlify("6f73").decode()
        # base64.b64decode("...").decode()
        if isinstance(node, ast.Call):
            return self._const_from_call(node)
        return None

    # --- inner: decode helper-call ---------------------------------------
    def _const_from_call(self, node: ast.Call) -> str | None:
        tgt = self.resolve_call_target(node.func)
        # bytes(literal_int_list)  e.g. bytes([111, 115])
        if tgt == "bytes" and len(node.args) == 1:
            arg = node.args[0]
            if isinstance(arg, ast.List) and all(
                isinstance(e, ast.Constant) and isinstance(e.value, int)
                for e in arg.elts
            ):
                try:
                    return bytes(e.value for e in arg.elts).decode("utf-8")  # type: ignore[attr-defined]
                except UnicodeDecodeError:
                    return None
        # bytes.fromhex("6f73") / binascii.unhexlify("6f73")
        if tgt in {"bytes.fromhex", "binascii.unhexlify"} and node.args:
            h = self.const_str(node.args[0])
            if h:
                try:
                    return bytes.fromhex(h).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    return None
        # str.encode()/decode() chains:  (...).decode()
        if isinstance(node.func, ast.Attribute) and node.func.attr == "decode":
            inner = node.func.value
            # base64.b64decode("...").decode()
            if isinstance(inner, ast.Call):
                inner_tgt = self.resolve_call_target(inner.func)
                if inner_tgt in {"base64.b64decode", "base64.b32decode",
                                 "base64.b16decode", "base64.a85decode"} \
                        and inner.args:
                    raw = self.const_str(inner.args[0])
                    if raw is None:
                        return None
                    try:
                        fn = {
                            "base64.b64decode": base64.b64decode,
                            "base64.b32decode": base64.b32decode,
                            "base64.b16decode": base64.b16decode,
                            "base64.a85decode": base64.a85decode,
                        }[inner_tgt]
                        return fn(raw).decode("utf-8", "replace")
                    except Exception:
                        return None
                # bytes.fromhex("...").decode()
                if inner_tgt == "bytes.fromhex" and inner.args:
                    h = self.const_str(inner.args[0])
                    if h:
                        try:
                            return bytes.fromhex(h).decode("utf-8")
                        except (ValueError, UnicodeDecodeError):
                            return None
            # "...".decode() on a Constant bytes
            const_bytes = inner if isinstance(inner, ast.Constant) else None
            if const_bytes and isinstance(const_bytes.value, bytes):
                try:
                    return const_bytes.value.decode("utf-8")
                except UnicodeDecodeError:
                    return None
        return None


# ---------------------------------------------------------------------------
# Visitor: walk the AST, emit Findings.
# ---------------------------------------------------------------------------

class _Visitor(ast.NodeVisitor):
    def __init__(self, file_repr: str, lines: list[str]) -> None:
        self.file = file_repr
        self.lines = lines
        self.findings: list[Finding] = []
        self.r = _Resolver()
        # name -> taint origin (e.g. "base64 decode"). Set on `x = <taint_src>(literal)`.
        self.tainted: dict[str, str] = {}

    # -- recording phase: imports, simple consts, taint ---------------------
    def visit_Import(self, node: ast.Import) -> None:
        self.r.record_import(node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.r.record_import(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.r.record_assign(node)
        # 单赋值额外处理
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            lhs = node.targets[0].id
            # 1. Module-ref 别名：mod = __import__('os')  / mod = importlib.import_module('os')
            #    之后 mod.system(...) 应该能解析成 os.system。
            mod = self.r.resolve_module_ref(node.value)
            if mod and isinstance(node.value, ast.Call):
                # 只对 Call rhs 记 alias（避免把 `x = some_var` 这种盲目当 alias）
                self.r.module_alias[lhs] = mod
            # 2. Taint propagation: x = <TAINT_SOURCE>(...)
            if isinstance(node.value, ast.Call):
                tgt = self.r.resolve_call_target(node.value.func)
                if tgt in TAINT_SOURCES:
                    self.tainted[lhs] = TAINT_SOURCES[tgt]
        self.generic_visit(node)

    # -- detection phase ----------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        target = self.r.resolve_call_target(node.func)

        # SC1: shell / subprocess
        if target in SHELL_SINKS:
            # 已知合法 CLI（libreoffice / pandoc / chromedriver 等）→ LOW
            arg0 = _subprocess_arg0(node)
            if arg0 and arg0 in KNOWN_DOC_AND_TOOL_BINARIES:
                self._record("SC1", node, "LOW", "execution",
                             f"AST: 调用 {target} 执行已知工具 {arg0!r}（合法用法）",
                             f"{target}([{arg0!r}, ...])")
            else:
                self._record("SC1", node, "HIGH", "execution",
                             f"AST: 调用 {target}", target)

        # SC2: dynamic code exec
        if target in DYNAMIC_EXEC_SINKS:
            self._record("SC2", node, "HIGH", "execution",
                         f"AST: 动态执行 {target}", target)
            # SC3 promotion: exec(<tainted>) / eval(<tainted>)
            if target in {"exec", "eval"} and node.args:
                a = node.args[0]
                if isinstance(a, ast.Name) and a.id in self.tainted:
                    src = self.tainted[a.id]
                    self._record("SC3", node, "CRITICAL", "evasion",
                                 f"AST: {target}({a.id}) 中 {a.id} 来自 "
                                 f"{src}（污点链 → 任意代码执行）",
                                 f"{target}(<{src}>)")
                # exec(compile(open(...).read(), ...))  — common stage-2 loader
                if isinstance(a, ast.Call):
                    inner_t = self.r.resolve_call_target(a.func)
                    if inner_t == "compile":
                        self._record("SC3", node, "HIGH", "evasion",
                                     f"AST: {target}(compile(...)) 模式，"
                                     "常用于从外部文件/网络加载二阶 payload",
                                     f"{target}(compile(...))")

        # SC3: deserialization sinks
        if target in SERIALIZATION_SINKS:
            self._record("SC3", node, SERIALIZATION_SINKS[target], "evasion",
                         f"AST: 反序列化 {target}（不可信输入 → 任意代码执行）",
                         target)

        # SC3: native libraries
        if target in NATIVE_LIB_SINKS:
            self._record("SC3", node, "HIGH", "evasion",
                         f"AST: 加载本地库 {target}（AST 无法审计 .so/.dll 内容）",
                         target)

        # SC2: code-object constructors
        if target in CODE_OBJECT_BUILDERS:
            self._record("SC2", node, "HIGH", "execution",
                         f"AST: 构造 code/function 对象 {target}", target)

        # SC2: frame escape (used to reach __builtins__)
        if target in FRAME_ESCAPE_SINKS:
            self._record("SC2", node, "MEDIUM", "evasion",
                         f"AST: 帧逃逸 {target}（典型用法：拿 __builtins__）",
                         target)

        # E1: network exfil & DNS tunnel
        if target in NETWORK_EXFIL_SINKS:
            sev = "MEDIUM"
            desc = f"AST: 外联 {target}"
            # DNS exfil heuristic: gethostbyname(<encoded data> + '.<domain>')
            if target in {"socket.gethostbyname", "socket.gethostbyname_ex"} \
                    and node.args:
                if self._arg_looks_like_dns_tunnel(node.args[0]):
                    sev = "HIGH"
                    desc = ("AST: gethostbyname 的主机名由编码数据拼装而来 — "
                            "DNS 隧道外渗模式")
            self._record("E1", node, sev, "exfil", desc, target)

        # Universal jailbreak: <expr>.__subclasses__()
        if isinstance(node.func, ast.Attribute) \
                and node.func.attr == "__subclasses__":
            self._record("SC2", node, "CRITICAL", "evasion",
                         "AST: ().__class__.__mro__/__subclasses__() 链 — "
                         "通用沙箱越狱手法，借 object 子类找 file/popen",
                         "<obj>.__subclasses__()")

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # E2: os.environ["SENSITIVE_KEY"]
        base = self.r.resolve_module_ref(node.value)
        key = self.r.const_str(node.slice)
        if base == "os.environ" and key:
            if key not in SAFE_ENV_WHITELIST \
                    and SENSITIVE_ENV_PATTERN.search(key):
                self._record("E2", node, "MEDIUM", "cred_access",
                             f"AST: 读敏感环境变量 {key!r}",
                             f"os.environ[{key!r}]")
        # globals()['__builtins__']  /  globals()['__import__']
        if isinstance(node.value, ast.Call) \
                and isinstance(node.value.func, ast.Name) \
                and node.value.func.id == "globals" \
                and key in {"__builtins__", "__import__", "__loader__"}:
            self._record("SC2", node, "HIGH", "evasion",
                         f"AST: globals()[{key!r}] 访问解释器内置 "
                         "（沙箱越狱常见手法）",
                         f"globals()[{key!r}]")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # os.environ.get("AWS_SECRET_ACCESS_KEY")
        # We catch this in visit_Call when the outer node is the call;
        # here we handle the bare-attribute form: x = os.environ["..."]
        # Already covered by visit_Subscript above.
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        guard = self._sniff_dormancy_guard(node.test)
        if guard and self._body_has_dangerous_call(node.body):
            self._record("SC2", node, "HIGH", "evasion",
                         f"AST: 危险调用被 {guard} 保护 — "
                         "潜在 dormant payload / time bomb / target fence",
                         f"if <{guard}> ...")
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        # Common evasion: deliberately raise, then hide the real call in except
        for handler in node.handlers:
            if self._body_has_dangerous_call(handler.body):
                self._record("SC2", handler, "MEDIUM", "evasion",
                             "AST: except 分支中藏有危险调用 — "
                             "故意触发异常以转移控制流",
                             "except: <danger>")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Decorators run at import/class-definition time. If the decorator
        # is itself a Call with a dangerous body or the decorator references
        # a function whose body has a dangerous call, that's a definition-time
        # side effect.
        self.generic_visit(node)
        # Heuristic: if any module-level function is used as decorator AND
        # contains a dangerous call, flag the class/function that uses it.
        # (Resolved coarsely below in visit_ClassDef / by scanning decorators.)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scan_decorators(node.decorator_list, node, kind="class")
        self.generic_visit(node)

    # -- helpers ------------------------------------------------------------
    def _scan_decorators(self, decorators: list[ast.expr],
                         owner: ast.AST, kind: str) -> None:
        for dec in decorators:
            # @some_call(...)
            if isinstance(dec, ast.Call):
                t = self.r.resolve_call_target(dec.func)
                if t in SHELL_SINKS or t in DYNAMIC_EXEC_SINKS:
                    self._record("SC2", dec, "HIGH", "execution",
                                 f"AST: 装饰器在 {kind} 定义时调用 {t} — "
                                 "任意 import 即触发",
                                 f"@{t}(...)")
            # @bare_name 但 bare_name 本身在本模块定义且含危险调用
            if isinstance(dec, ast.Name):
                fn_body = self._lookup_function_body(dec.id)
                if fn_body and self._body_has_dangerous_call(fn_body):
                    self._record("SC2", dec, "HIGH", "execution",
                                 f"AST: 装饰器 @{dec.id} 在 {kind} 定义时执行，"
                                 f"且其函数体含危险调用 — import 即触发",
                                 f"@{dec.id}")

    def _lookup_function_body(self, name: str) -> list[ast.stmt] | None:
        # Naive: scan the top-level for a FunctionDef matching `name`.
        # Good enough for the decorator-time test sample.
        # We don't carry a module ref here; the caller scans within the tree.
        return getattr(self, "_function_table", {}).get(name)

    def _sniff_dormancy_guard(self, expr: ast.AST) -> str | None:
        """Return a label if `expr` looks like a dormancy guard.

        Matches:
            time.time() > N
            time.time() < N (anti time-bomb: only fires before deadline)
            socket.gethostname() == "..."
            platform.node() in {...}
            datetime.datetime.now() > datetime(2026, ...)
        """
        if isinstance(expr, ast.Compare) and isinstance(expr.left, ast.Call):
            t = self.r.resolve_call_target(expr.left.func)
            if t in DORMANCY_GUARDS:
                return f"{t}() {DORMANCY_GUARDS[t]}"
        # `in {...}` form
        if isinstance(expr, ast.Compare) and isinstance(expr.left, ast.Call) \
                and any(isinstance(op, (ast.In, ast.NotIn)) for op in expr.ops):
            t = self.r.resolve_call_target(expr.left.func)
            if t in DORMANCY_GUARDS:
                return f"{t}() {DORMANCY_GUARDS[t]}"
        return None

    def _body_has_dangerous_call(self, body: list[ast.stmt]) -> bool:
        for stmt in body:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call):
                    t = self.r.resolve_call_target(sub.func)
                    if t in SHELL_SINKS or t in DYNAMIC_EXEC_SINKS:
                        return True
                # `.__subclasses__()` chain
                if isinstance(sub, ast.Attribute) and sub.attr == "__subclasses__":
                    return True
        return False

    def _arg_looks_like_dns_tunnel(self, arg: ast.AST) -> bool:
        """Heuristic: `<encoded>(.decode())? + ".attacker.tld"`. We look for
        any string concatenation where at least one operand is the result of
        a base64/b32/b16/hex encode call, and the other operand is a
        constant string that contains '.' (a fake domain)."""
        if not isinstance(arg, ast.BinOp) or not isinstance(arg.op, ast.Add):
            return False
        operands: list[ast.AST] = []
        # flatten nested adds
        stack = [arg]
        while stack:
            n = stack.pop()
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                stack.extend([n.right, n.left])
            else:
                operands.append(n)
        has_encoded = False
        has_domain = False
        for op in operands:
            # .decode() on a base*encode(...) call → encoded
            if isinstance(op, ast.Call) and isinstance(op.func, ast.Attribute):
                if op.func.attr in {"decode", "lower", "upper"} \
                        and isinstance(op.func.value, ast.Call):
                    inner_t = self.r.resolve_call_target(op.func.value.func)
                    if inner_t in {"base64.b64encode", "base64.b32encode",
                                   "base64.b16encode", "base64.a85encode",
                                   "binascii.hexlify"}:
                        has_encoded = True
            # naked encode call
            if isinstance(op, ast.Call):
                t = self.r.resolve_call_target(op.func)
                if t in {"base64.b64encode", "base64.b32encode",
                         "base64.b16encode", "base64.a85encode",
                         "binascii.hexlify"}:
                    has_encoded = True
            # constant string with a dot
            s = self.r.const_str(op)
            if s and "." in s and len(s) <= 80:
                has_domain = True
        return has_encoded and has_domain

    # -- emit ---------------------------------------------------------------
    def _record(self, rule_id: str, node: ast.AST, severity: str,
                phase: str, description: str, snippet: str) -> None:
        ln = getattr(node, "lineno", 1) or 1
        line_text = self.lines[ln - 1] if 1 <= ln <= len(self.lines) else ""
        evidence = EVIDENCE_TYPES.get(rule_id, "capability")
        self.findings.append(Finding(
            rule_id=rule_id,
            severity=severity,
            kill_chain_phase=phase,
            file=self.file,
            line=ln,
            pattern="<ast>",
            matched_text=snippet[:160],
            description=description,
            confidence=0.92,
            context="",
            original_severity=severity,
            evidence_type=evidence,
            context_type="main_skill_logic",
            snippet=line_text.strip()[:220],
            downgraded=False,
            downgrade_reason=None,
        ))


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_python_ast(path: Path | str, source: str) -> list[Finding]:
    """Run AST detection over a single .py source string.

    On `SyntaxError`, emit one SC3 finding flagging the file as
    unparseable — a real adversarial sample might deliberately corrupt
    the AST to evade scanning while still being importable via runtime
    string-build + exec elsewhere.
    """
    file_repr = str(path)
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [Finding(
            rule_id="SC3",
            severity="MEDIUM",
            kill_chain_phase="evasion",
            file=file_repr,
            line=e.lineno or 1,
            pattern="<ast-parse-fail>",
            matched_text=f"SyntaxError: {e.msg}"[:160],
            description=(
                "AST: .py 文件无法解析 "
                f"(line {e.lineno}: {e.msg}) — 可能为故意混淆"
            ),
            confidence=0.7,
            context="",
            original_severity="MEDIUM",
            evidence_type=EVIDENCE_TYPES.get("SC3", "evasion"),
            context_type="main_skill_logic",
            snippet=f"SyntaxError: {e.msg}"[:220],
        )]
    lines = source.splitlines()
    visitor = _Visitor(file_repr, lines)
    # Pre-pass: build a function table so decorator analysis can look up
    # bodies of functions defined in the same module.
    fn_table: dict[str, list[ast.stmt]] = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_table[stmt.name] = stmt.body
    visitor._function_table = fn_table  # type: ignore[attr-defined]
    visitor.visit(tree)
    return visitor.findings
