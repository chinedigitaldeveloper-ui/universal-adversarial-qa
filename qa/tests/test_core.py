import os
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import helpers  # noqa: F401  (adds qa/ to sys.path)
from helpers import PY, Harness, passing_check, policy_v2, setup_repo
import aqa_core as core


def process_alive(pid: int) -> bool:
    """A killed-but-unreaped child (zombie) is dead; plain kill(0) cannot tell the difference."""
    try:
        state = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()[0]
        return state not in ("Z", "X")
    except FileNotFoundError:
        pass
    except OSError:
        return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


class RedactionTests(unittest.TestCase):
    def test_known_token_shapes_are_redacted(self):
        samples = ["sk-" + "a" * 30, "ghp_" + "A" * 36, "github_pat_" + "B" * 40, "AKIA" + "Q" * 16,
                   "xoxb-" + "1" * 12 + "-abc"]
        for token in samples:
            self.assertNotIn(token, core.redact("value is %s here" % token))

    def test_private_key_block_and_bearer(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
        self.assertNotIn("MIIabc", core.redact("x\n%s\ny" % pem))
        self.assertNotIn("A" * 25, core.redact("Authorization: Bearer " + "A" * 25))

    def test_exact_env_secret_values_are_redacted_but_innocent_names_are_not(self):
        with patch.dict(os.environ, {"MY_SERVICE_TOKEN": "plainvalue-12345", "AUTHOR_NAME": "Jane Developer"}):
            text = core.redact("token=plainvalue-12345 by Jane Developer")
        self.assertNotIn("plainvalue-12345", text)
        self.assertIn("Jane Developer", text)

    def test_redact_obj_walks_nested_structures(self):
        out = core.redact_obj({"a": ["x sk-" + "z" * 30], "b": {"c": 3}})
        self.assertNotIn("z" * 30, str(out))
        self.assertEqual(out["b"]["c"], 3)


class EmitTests(unittest.TestCase):
    """CI log parsers execute lines that start with '::'. Untrusted text must never be able to produce one."""

    def capture(self, message):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            core.emit(message)
        return buf.getvalue()

    def test_embedded_newlines_cannot_start_a_new_line(self):
        out = self.capture("file a\n::set-output name=x::1\r\n::error::y")
        self.assertEqual(out.count("\n"), 1)                    # exactly the trailing newline
        self.assertFalse(any(line.startswith("::") for line in out.splitlines()))

    def test_a_message_that_itself_starts_with_command_syntax_is_neutralized(self):
        self.assertFalse(self.capture("::warning::from data").startswith("::"))
        self.assertFalse(self.capture("   ::warning::indented").lstrip().startswith("::"))
        self.assertEqual(self.capture("plain message"), "plain message\n")


class EnvironmentTests(unittest.TestCase):
    def test_provider_and_cloud_secrets_are_not_inherited(self):
        source = {"PATH": "/bin", "HOME": "/h", "OPENAI_API_KEY": "k", "GITHUB_TOKEN": "t", "AWS_SECRET_ACCESS_KEY": "s",
                  "DATABASE_URL": "postgres://u:p@h/db", "LC_ALL": "C", "JAVA_HOME": "/j"}
        env = core.scrubbed_env(source=source)
        self.assertEqual(set(env), {"PATH", "HOME", "LC_ALL", "JAVA_HOME"})

    def test_explicit_passthrough_and_static_extra(self):
        source = {"PATH": "/bin", "NPM_TOKEN": "t", "DATABASE_URL": "d"}
        env = core.scrubbed_env(["NPM_TOKEN", "DATABASE_URL"], {"FOO": "bar"}, source)
        self.assertEqual(env["NPM_TOKEN"], "t")
        self.assertEqual(env["DATABASE_URL"], "d")
        self.assertEqual(env["FOO"], "bar")


class ProcessTests(unittest.TestCase):
    def test_timeout_kills_the_whole_process_group_quickly(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / "child.pid"
            script = ("import subprocess,sys,time;"
                      "p=subprocess.Popen(['sleep','60']);open(%r,'w').write(str(p.pid));time.sleep(60)" % str(pidfile))
            started = time.monotonic()
            result = core.run_process([PY, "-c", script], Path(tmp), seconds=2)
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["code"], 124)
            self.assertLess(time.monotonic() - started, 15)
            pid = int(pidfile.read_text())
            time.sleep(0.5)
            self.assertFalse(process_alive(pid), "grandchild survived the timeout")

    def test_stdin_is_closed(self):
        result = core.run_process([PY, "-c", "import sys;print(repr(sys.stdin.read()))"], Path("."), 10)
        self.assertEqual(result["stdout"].strip(), "''")

    def test_missing_executable_is_127(self):
        self.assertEqual(core.run_process(["definitely-not-installed-xyz"], Path("."), 5)["code"], 127)

    def test_output_is_tailed_and_flagged(self):
        result = core.run_process([PY, "-c", "print('x'*5000)"], Path("."), 10, max_output=100)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["stdout"]), 100)


class SchemaTests(unittest.TestCase):
    def test_subset_validator(self):
        schema = {"type": "object", "required": ["a"], "additionalProperties": False,
                  "properties": {"a": {"type": "integer", "minimum": 1}, "b": {"enum": ["x"]},
                                 "c": {"$ref": "#/definitions/d"}},
                  "definitions": {"d": {"type": "array", "items": {"type": "string"}}}}
        self.assertEqual(core.validate_json({"a": 1, "b": "x", "c": ["s"]}, schema), [])
        self.assertTrue(core.validate_json({"a": True}, schema))            # bool is not an integer
        self.assertTrue(core.validate_json({"a": 0}, schema))               # minimum
        self.assertTrue(core.validate_json({"a": 1, "z": 1}, schema))       # additionalProperties
        self.assertTrue(core.validate_json({"a": 1, "c": [1]}, schema))     # $ref + items
        self.assertTrue(core.validate_json({}, schema))                     # required


class GitHelperTests(Harness):
    def test_merge_base_and_out_dir_exclusion(self):
        setup_repo(self.repo)
        base, merge_base, warning = core.resolve_base(self.repo, "main")
        self.assertEqual(base, merge_base)
        self.assertEqual(warning, "")
        out = self.repo / ".qa" / "out"
        out.mkdir(parents=True)
        (out / "report.json").write_text("{}")
        (self.repo / "new file.txt").write_text("x\n")
        files = core.changed_files(self.repo, merge_base, exclude_dir=out)
        self.assertIn("demo.txt", files)
        self.assertIn("new file.txt", files)
        self.assertFalse(any(f.startswith(".qa/out") for f in files))
        counts = core.diff_numstat(self.repo, merge_base, files)
        self.assertEqual(counts["demo.txt"], 1)
        self.assertEqual(counts["new file.txt"], 1)


if __name__ == "__main__":
    unittest.main()
