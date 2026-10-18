"""code_sandbox 安全与功能测试。"""

from __future__ import annotations

import os

import pytest

from plugin.plugins.code_sandbox.sandbox import (
    MAX_OUTPUT_CHARS,
    SandboxViolation,
    _sanitized_env,
    audit_code,
    run_code,
)

# ══════════ audit_code ══════════


def test_audit_allows_pure_calculation() -> None:
    code = (
        "import math, random, json\n"
        "def f(x):\n"
        "    return x * 2\n"
        "print(f(21), math.pi, random.randint(1, 2))\n"
    )
    audit_code(code)  # 不应抛异常


def test_audit_blocks_os_import() -> None:
    with pytest.raises(SandboxViolation, match="os"):
        audit_code("import os\nprint(os.getcwd())\n")


def test_audit_blocks_subprocess_import() -> None:
    with pytest.raises(SandboxViolation, match="subprocess"):
        audit_code("from subprocess import run\n")


def test_audit_blocks_socket_import() -> None:
    with pytest.raises(SandboxViolation, match="socket"):
        audit_code("import socket\n")


def test_audit_blocks_pathlib() -> None:
    with pytest.raises(SandboxViolation, match="pathlib"):
        audit_code("from pathlib import Path\n")


def test_audit_blocks_eval_exec() -> None:
    with pytest.raises(SandboxViolation, match="eval"):
        audit_code("eval('1+1')\n")
    with pytest.raises(SandboxViolation, match="exec"):
        audit_code("exec('x=1')\n")


def test_audit_blocks_open_call() -> None:
    with pytest.raises(SandboxViolation, match="open"):
        audit_code("f = open('x.txt', 'w')\n")


def test_audit_blocks_builtins_attribute_open() -> None:
    with pytest.raises(SandboxViolation, match="open"):
        audit_code("__builtins__.open('evil.txt', 'w')\n")


def test_audit_blocks_dangerous_attribute() -> None:
    with pytest.raises(SandboxViolation, match="system"):
        audit_code("import os\nos.system('dir')\n")


def test_audit_blocks_getattr() -> None:
    with pytest.raises(SandboxViolation, match="getattr"):
        audit_code("getattr(__builtins__, 'open')\n")


def test_audit_rejects_syntax_error() -> None:
    with pytest.raises(SandboxViolation, match="语法错误"):
        audit_code("def broken(:\n")


# ══════════ run_code ══════════


def test_run_code_success() -> None:
    result = run_code("import math\nprint(sum(n for n in range(1, 101)))\n")
    assert result["is_error"] is False
    assert "5050" in result["output"]


def test_run_code_empty() -> None:
    result = run_code("   ")
    assert result["is_error"] is True
    assert "NO_CODE" in result["error"]


def test_run_code_violation_is_rejected() -> None:
    result = run_code("import os\nprint(os.getcwd())\n")
    assert result["is_error"] is True
    assert result["error"] == "SANDBOX_VIOLATION"
    assert "安全拦截" in result["output"]


def test_run_code_runtime_error() -> None:
    result = run_code("1 / 0\n")
    assert result["is_error"] is True
    assert result["error"] == "RUNTIME_ERROR"


def test_run_code_timeout_kills() -> None:
    result = run_code("while True:\n    pass\n", timeout=1)
    assert result["is_error"] is True
    assert result["error"] == "TIMEOUT"


def test_sanitized_env_strips_api_keys() -> None:
    os.environ["DASHSCOPE_API_KEY"] = "test-secret-123"
    os.environ["KLING_SECRET_KEY"] = "kling-secret"
    try:
        env = _sanitized_env()
    finally:
        os.environ.pop("DASHSCOPE_API_KEY", None)
        os.environ.pop("KLING_SECRET_KEY", None)
    assert "DASHSCOPE_API_KEY" not in env
    assert "KLING_SECRET_KEY" not in env
    # 普通变量保留
    os.environ["TMP"] = os.environ.get("TMP", "C:\\Temp")
    env2 = _sanitized_env()
    assert "TMP" in env2


def test_truncation_limit_exists() -> None:
    assert MAX_OUTPUT_CHARS == 50000
