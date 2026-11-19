"""CLI 端到端测试：以子进程运行全部命令，检查退出码与 JSON 输出。"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mirror_auth.generator import (
    crafted_connections,
    crafted_policy_batches,
    write_jsonl,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


class CliTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.db = self.base / "p.db"
        self.workdir = self.base / "work"
        self.conn_file = self.base / "connections.jsonl"
        write_jsonl(self.conn_file, crafted_connections())
        self.batch_files = []
        for idx, batch in enumerate(crafted_policy_batches(), start=1):
            path = self.base / f"gen{idx}.jsonl"
            write_jsonl(path, batch)
            self.batch_files.append(path)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args, expect_code=0):
        # 从不含任何代码的中性目录启动，避免解释器把 cwd 放进 sys.path
        # 而误导入同目录文件；PYTHONPATH 只指向仓库根。普通隔离模式
        # （不带 -I）仍屏蔽用户 site-packages，且解释器加载的只有
        # 仓库内受信任的 mirror_auth 包。
        neutral_cwd = Path(self.tmp.name) / "_neutral_cwd"
        neutral_cwd.mkdir(exist_ok=True)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT)
        env["PYTHONNOUSERSITE"] = "1"
        proc = subprocess.run(
            [sys.executable, "-s", "-m", "mirror_auth", *args],
            cwd=neutral_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
        )
        self.assertEqual(
            proc.returncode, expect_code,
            msg=f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}",
        )
        return proc

    def test_full_command_lifecycle(self):
        # 1. 三代策略发布
        for idx, batch in enumerate(self.batch_files, start=1):
            proc = self._run("apply-policy", "--db", str(self.db),
                             "--batch", str(batch))
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["generation"], idx)

        # 2. explain：不允许出现任何实际字段值（只含 ID/证据/理由）
        proc = self._run("explain", "--db", str(self.db),
                         "--connections", str(self.conn_file))
        lines = [json.loads(x) for x in proc.stdout.splitlines()]
        self.assertEqual(len(lines), len(crafted_connections()))
        denied = next(x for x in lines
                      if x["connection_id"] == "c-narrow-deny-03")
        self.assertTrue(denied["denied"])
        self.assertEqual(denied["first_deny"]["rule_id"],
                         "g1-deny-b-recv-a-narrow")
        allowed = next(x for x in lines
                       if x["connection_id"] == "c-allowed-01")
        self.assertIn("evidence", allowed["fields"]["dst_port"])
        # 实际字段值 443 / 192.0.2.10 绝不能出现在 explain 输出里
        self.assertNotIn("443", proc.stdout)
        self.assertNotIn("192.0.2.10", proc.stdout)

        # 3. 历史代次 explain：gen1 下 risk_score 缺一侧审批
        proc = self._run("explain", "--db", str(self.db),
                         "--connections", str(self.conn_file),
                         "--generation", "1")
        gen1_lines = [json.loads(x) for x in proc.stdout.splitlines()]
        g1_allowed = next(x for x in gen1_lines
                          if x["connection_id"] == "c-allowed-01")
        self.assertFalse(g1_allowed["fields"]["risk_score"]["allowed"])
        self.assertIn("审批", g1_allowed["fields"]["risk_score"]["reason"])

        # 4. export + 重放
        proc = self._run("export", "--db", str(self.db),
                         "--workdir", str(self.workdir),
                         "--connections", str(self.conn_file),
                         "--receiver-zone", "zone-b",
                         "--request-id", "rid-1")
        first = json.loads(proc.stdout)
        self.assertEqual(first["status"], "published")

        proc = self._run("export", "--db", str(self.db),
                         "--workdir", str(self.workdir),
                         "--connections", str(self.conn_file),
                         "--receiver-zone", "zone-b",
                         "--request-id", "rid-1")
        self.assertEqual(json.loads(proc.stdout)["status"], "replayed")

        # 5. verify
        proc = self._run("verify", "--db", str(self.db),
                         "--workdir", str(self.workdir),
                         "--connections", str(self.conn_file),
                         "--request-id", "rid-1")
        report = json.loads(proc.stdout)
        self.assertTrue(report["ok"])

        # 6. receipts / recover
        proc = self._run("receipts", "--db", str(self.db))
        self.assertIn("rid-1", proc.stdout)
        proc = self._run("recover", "--db", str(self.db),
                         "--workdir", str(self.workdir))
        self.assertEqual(json.loads(proc.stdout)["removed"], 0)

    def test_conflict_exit_code(self):
        self._run("apply-policy", "--db", str(self.db),
                 "--batch", str(self.batch_files[0]))
        self._run("export", "--db", str(self.db),
                  "--workdir", str(self.workdir),
                  "--connections", str(self.conn_file),
                  "--receiver-zone", "zone-b", "--request-id", "rid-x")
        altered = self.base / "altered.jsonl"
        records = [json.loads(x) for x in
                   self.conn_file.read_text(encoding="utf-8").splitlines()]
        records[0]["dst_port"] = 12321
        write_jsonl(altered, records)
        self._run("export", "--db", str(self.db),
                  "--workdir", str(self.workdir),
                  "--connections", str(altered),
                  "--receiver-zone", "zone-b", "--request-id", "rid-x",
                  expect_code=3)

    def test_verify_missing_receipt_exit_code(self):
        # 代次竞态过时路径（退出码 4）由库级测试覆盖；
        # 这里验证 CLI 对不存在回执的 verify 返回业务错误码
        self._run("apply-policy", "--db", str(self.db),
                 "--batch", str(self.batch_files[0]))
        self._run("verify", "--db", str(self.db),
                  "--workdir", str(self.workdir),
                  "--connections", str(self.conn_file),
                  "--request-id", "missing", expect_code=1)

    def test_demo_generator(self):
        outdir = self.base / "demo"
        proc = self._run("generate", "demo", "--outdir", str(outdir))
        payload = json.loads(proc.stdout)
        self.assertTrue(Path(payload["connections"]).is_file())
        self.assertEqual(len(payload["policy_batches"]), 3)


if __name__ == "__main__":
    unittest.main()
