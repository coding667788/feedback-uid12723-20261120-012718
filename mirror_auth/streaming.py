"""流式 JSONL 读取与输入摘要。

连接文件按 JSON Lines 存储，逐行解析、逐条产出，十万条连接也只有
单条连接常驻内存。输入摘要对“每行去空白后的原始 UTF-8 字节”做
SHA-256（每行仍经 JSON 解析与连接校验），与记录内容、记录顺序
严格绑定，空行差异不影响摘要。
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .models import Connection


def iter_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    """逐行产出 JSON 对象，空行跳过，错误带行号报告。"""
    for obj, _line in iter_jsonl_with_line(path):
        yield obj


def iter_jsonl_with_line(
    path: str | Path,
) -> Iterator[tuple[dict[str, Any], str]]:
    """逐行产出 (JSON 对象, 去除首尾空白的原始行文本)。"""
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                obj = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno} 不是合法 JSON: {exc.msg}") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"{path}:{lineno} 每行必须是 JSON 对象")
            yield obj, text


def iter_connections(path: str | Path) -> Iterator[Connection]:
    """逐行校验并产出 :class:`Connection`。"""
    for lineno, (raw, _line) in enumerate(
        iter_jsonl_with_line(path), start=1
    ):
        try:
            yield Connection.from_dict(raw)
        except ValueError as exc:
            raise ValueError(f"{path}:{lineno} 连接校验失败: {exc}") from exc


def iter_connections_with_digest(
    path: str | Path,
) -> Iterator[tuple[Connection, bytes]]:
    """单趟同时产出连接对象与参与输入摘要的字节。

    每行只做一次 JSON 解析（语义校验），摘要直接累积“去空白后的原始
    行字节 + 换行”：同一文件重放必然字节一致；任意字段值或记录顺序
    改变都会改变摘要。免去对每行再做一次规范化 JSON 序列化。
    """
    for lineno, (raw, text) in enumerate(
        iter_jsonl_with_line(path), start=1
    ):
        try:
            conn = Connection.from_dict(raw)
        except ValueError as exc:
            raise ValueError(f"{path}:{lineno} 连接校验失败: {exc}") from exc
        yield conn, text.encode("utf-8") + b"\n"


def compute_input_digest(path: str | Path) -> str:
    """单趟计算输入摘要（SHA-256 十六进制）。

    摘要输入 = 每行去空白后的原始 UTF-8 字节 + ``\\n``；每行仍经
    JSON 解析与连接校验。记录内容或顺序变化都会改变摘要。
    """
    digest = hashlib.sha256()
    for _conn, chunk in iter_connections_with_digest(path):
        digest.update(chunk)
    return digest.hexdigest()


def digest_jsonl(path: str | Path) -> str:
    """输入摘要的语义化别名（保留向后兼容的公开名）。"""
    return compute_input_digest(path)


def digest_file(path: str | Path) -> str:
    """对完整产物文件做 SHA-256（分块读取，避免大文件入内存）。"""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
