"""命令行入口：apply-policy / explain / export / verify，外加生成与恢复辅助。

用法总览::

    python -m mirror_auth apply-policy --db DB --batch FILE
    python -m mirror_auth explain       --db DB --connections FILE [--generation N]
    python -m mirror_auth export        --db DB --workdir DIR --connections FILE \
                                        --receiver-zone Z --request-id ID
    python -m mirror_auth verify        --db DB --workdir DIR --connections FILE \
                                        --request-id ID
    python -m mirror_auth generate connections --count N --seed S --out FILE
    python -m mirror_auth generate demo --outdir DIR
    python -m mirror_auth receipts      --db DB
    python -m mirror_auth recover       --db DB --workdir DIR

退出码：0 成功；1 业务/校验错误；2 参数错误；3 输入冲突；4 代次过时。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import __version__
from .export import (
    STATUS_STALE,
    InputConflictError,
    reconcile_artifacts,
    run_export,
)
from .explain import write_explanations
from .generator import (
    crafted_connections,
    crafted_policy_batches,
    generate_connections,
    write_jsonl,
)
from .models import dumps_canonical, validate_event
from .storage import Storage
from .streaming import iter_jsonl
from .timeutil import now_micros
from .verifier import VerificationError, verify_receipt

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_CONFLICT = 3
EXIT_STALE = 4


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m mirror_auth",
        description="跨安全区网络流量镜像双边授权模拟器（纯标准库 + SQLite）",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_apply = sub.add_parser("apply-policy", help="原子发布一批策略事件")
    p_apply.add_argument("--db", required=True)
    p_apply.add_argument("--batch", required=True,
                         help="JSONL 策略事件文件（approval/deny/revocation）")

    p_explain = sub.add_parser("explain", help="逐条解释裁定，不打印字段值")
    p_explain.add_argument("--db", required=True)
    p_explain.add_argument("--connections", required=True)
    p_explain.add_argument("--generation", type=int, default=None,
                           help="绑定历史代次查询；默认当前代次")

    p_export = sub.add_parser("export", help="流式导出最小授权产物并公布回执")
    p_export.add_argument("--db", required=True)
    p_export.add_argument("--workdir", required=True,
                          help="产物暂存目录（artifacts/ 位于其下）")
    p_export.add_argument("--connections", required=True)
    p_export.add_argument("--receiver-zone", required=True)
    p_export.add_argument("--request-id", required=True)

    p_verify = sub.add_parser("verify", help="按绑定代次独立核对产物与证据")
    p_verify.add_argument("--db", required=True)
    p_verify.add_argument("--workdir", required=True)
    p_verify.add_argument("--connections", required=True)
    p_verify.add_argument("--request-id", required=True)

    p_gen = sub.add_parser("generate", help="生成合成输入")
    gen_sub = p_gen.add_subparsers(dest="generate_target", required=True)
    g_conn = gen_sub.add_parser("connections", help="随机合成连接")
    g_conn.add_argument("--count", type=int, required=True)
    g_conn.add_argument("--seed", type=int, default=20261120)
    g_conn.add_argument("--out", required=True)
    g_demo = gen_sub.add_parser("demo", help="生成小样本演示夹具与三代策略")
    g_demo.add_argument("--outdir", required=True)
    g_pol = gen_sub.add_parser("policies", help="随机策略批次（规模测试）")
    g_pol.add_argument("--batch-no", type=int, required=True)
    g_pol.add_argument("--seed", type=int, default=7)
    g_pol.add_argument("--out", required=True)

    p_rec = sub.add_parser("receipts", help="列出全部导出回执")
    p_rec.add_argument("--db", required=True)

    p_recov = sub.add_parser("recover", help="清理无回执的孤儿暂存产物")
    p_recov.add_argument("--db", required=True)
    p_recov.add_argument("--workdir", required=True)
    return parser


def _cmd_apply(storage: Storage, args: argparse.Namespace) -> int:
    raw_events = list(iter_jsonl(args.batch))
    if not raw_events:
        raise ValueError("策略批次为空，拒绝发布")
    events = [validate_event(raw) for raw in raw_events]
    batch_digest = hashlib.sha256(
        ("\n".join(dumps_canonical(e) for e in events)).encode("utf-8")
    ).hexdigest()
    generation = storage.publish_generation(events, batch_digest, now_micros())
    json.dump(
        {"generation": generation, "event_count": len(events),
         "batch_digest": batch_digest},
        sys.stdout, ensure_ascii=False, sort_keys=True,
    )
    sys.stdout.write("\n")
    return EXIT_OK


def _cmd_explain(storage: Storage, args: argparse.Namespace) -> int:
    count = write_explanations(
        storage, args.connections, sys.stdout, generation=args.generation
    )
    return EXIT_OK if count else EXIT_OK


def _cmd_export(storage: Storage, args: argparse.Namespace) -> int:
    result = run_export(
        storage=storage,
        workdir=args.workdir,
        input_path=args.connections,
        receiver_zone=args.receiver_zone,
        request_id=args.request_id,
    )
    if result["status"] == STATUS_STALE:
        json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True)
        sys.stdout.write("\n")
        return EXIT_STALE
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_OK


def _cmd_verify(storage: Storage, args: argparse.Namespace) -> int:
    report = verify_receipt(storage, args.request_id, args.connections)
    json.dump(report, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_OK


def _cmd_generate(args: argparse.Namespace) -> int:
    if args.generate_target == "connections":
        if args.count <= 0:
            raise ValueError("--count 必须为正整数")
        records = generate_connections(args.count, args.seed)
        write_jsonl(args.out, records)
        print(json.dumps({"out": args.out, "count": len(records)},
                         ensure_ascii=False))
    elif args.generate_target == "policies":
        from .generator import generate_policy_batch
        records = generate_policy_batch(args.batch_no, args.seed)
        write_jsonl(args.out, records)
        print(json.dumps({"out": args.out, "count": len(records)},
                         ensure_ascii=False))
    else:
        outdir = Path(args.outdir)
        conns_path = outdir / "connections.jsonl"
        write_jsonl(conns_path, crafted_connections())
        for idx, batch in enumerate(crafted_policy_batches(), start=1):
            write_jsonl(outdir / f"policy-gen{idx}.jsonl", batch)
        print(json.dumps({
            "outdir": str(outdir),
            "connections": str(conns_path),
            "policy_batches": [
                str(outdir / f"policy-gen{idx}.jsonl")
                for idx in range(1, 4)
            ],
        }, ensure_ascii=False))
    return EXIT_OK


def _cmd_receipts(storage: Storage, args: argparse.Namespace) -> int:
    for receipt in storage.list_receipts():
        json.dump(receipt, sys.stdout, ensure_ascii=False, sort_keys=True)
        sys.stdout.write("\n")
    return EXIT_OK


def _cmd_recover(storage: Storage, args: argparse.Namespace) -> int:
    result = reconcile_artifacts(storage, args.workdir)
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "generate":
        try:
            return _cmd_generate(args)
        except (OSError, ValueError) as exc:
            print(f"错误: {exc}", file=sys.stderr)
            return EXIT_ERROR

    storage = Storage(args.db)
    try:
        if args.command == "apply-policy":
            handler = lambda: _cmd_apply(storage, args)
        elif args.command == "explain":
            handler = lambda: _cmd_explain(storage, args)
        elif args.command == "export":
            handler = lambda: _cmd_export(storage, args)
        elif args.command == "verify":
            handler = lambda: _cmd_verify(storage, args)
        elif args.command == "receipts":
            handler = lambda: _cmd_receipts(storage, args)
        elif args.command == "recover":
            handler = lambda: _cmd_recover(storage, args)
        else:  # pragma: no cover - argparse 已拦截
            parser.error(f"未知命令 {args.command}")

        try:
            return handler()
        except InputConflictError as exc:
            print(f"错误: {exc}", file=sys.stderr)
            return EXIT_CONFLICT
        except VerificationError as exc:
            print(f"核对失败: {exc}", file=sys.stderr)
            return EXIT_ERROR
        except (ValueError, OSError, RuntimeError) as exc:
            print(f"错误: {exc}", file=sys.stderr)
            return EXIT_ERROR
    finally:
        storage.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
