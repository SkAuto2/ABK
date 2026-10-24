"""Regression tests for SukiSU/BakaSU selinux_hide/SUSFS compatibility patches."""
import ast
import importlib.util
import re
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/fix_sukisu_susfs.py"


BASE_SOURCE = textwrap.dedent(
    """\
    #include <linux/fs.h>
    #include <linux/mutex.h>

    static struct selinux_state fake_state;
    static bool ksu_selinux_hide_running __read_mostly = false;
    static bool ksu_selinux_hide_enabled __read_mostly = false;

    static ssize_t my_write_context(struct file *file, char *buf, size_t size)
    {
        return 0;
    }

    static ssize_t my_write_access(struct file *file, char *buf, size_t size)
    {
        return 0;
    }

    static int my_setprocattr(const char *name, void *value, size_t size);
    static int __nocfi my_setprocattr(const char *name, void *value, size_t size)
    {
        return 0;
    }
    """
)


class SukiSUSUSFSCompatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("fix_sukisu_susfs", SCRIPT)
        cls.patcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.patcher)

    def patch(self, source):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "selinux_hide.c"
            path.write_text(source, encoding="utf-8")
            changed = []
            self.patcher.patch_selinux_hide(path, changed)
            patched = path.read_text(encoding="utf-8")
            self.assertTrue(changed)

            # The workflow may execute this script more than once; the second
            # pass must be a no-op and must not duplicate the compatibility
            # declarations.
            changed_again = []
            self.patcher.patch_selinux_hide(path, changed_again)
            self.assertEqual(changed_again, [])
            self.assertEqual(path.read_text(encoding="utf-8"), patched)
            return patched

    def test_exports_susfs_hooks_and_adds_preinit_stubs(self):
        patched = self.patch(BASE_SOURCE)

        self.assertNotIn("static ssize_t my_write_context(", patched)
        self.assertNotIn("static ssize_t my_write_access(", patched)
        self.assertNotIn("static int my_setprocattr(", patched)
        self.assertNotIn("static int __nocfi my_setprocattr(", patched)
        self.assertIn("ssize_t my_write_context(", patched)
        self.assertIn("ssize_t my_write_access(", patched)
        self.assertIn("int my_setprocattr(", patched)
        self.assertIn("int __nocfi my_setprocattr(", patched)

        self.assertIn("struct filename;", patched)
        self.assertIn("struct user_arg_ptr;", patched)
        self.assertIn("int ksu_setup_preinit_file(", patched)
        self.assertIn("int ksu_preinit_handle_post_execveat(", patched)
        self.assertNotIn("struct selinux_state static fake_state", patched)
        self.assertIn("struct selinux_state fake_state;", patched)

    def test_fake_state_is_optional_for_newer_sukisu(self):
        source = BASE_SOURCE.replace("static struct selinux_state fake_state;\n", "")
        patched = self.patch(source)

        self.assertNotIn("fake_state", patched)
        self.assertIn("int ksu_setup_preinit_file(", patched)


class BakaSUSUSFSCompatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = ROOT / ".github/workflows/build.yml"
        step = workflow.read_text(encoding="utf-8").split("- name: 修复 BakaSU SUSFS 源码兼容", 1)[1]
        code = textwrap.dedent(step.split("python3 - <<'PY'\n", 1)[1].split("\n          PY", 1)[0])
        functions = [node for node in ast.parse(code).body if isinstance(node, ast.FunctionDef)]
        cls.namespace = {"re": re}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(workflow), "exec"), cls.namespace)

    def test_exports_old_and_current_sources_idempotently(self):
        source = """\
#include <linux/mutex.h>
__maybe_static bool ksu_selinux_hide_running __read_mostly = false;
__maybe_static bool ksu_selinux_hide_enabled __read_mostly = false;
__maybe_static DEFINE_STATIC_KEY_FALSE(fake_status_initialize_key);
__maybe_static struct page *fake_status = NULL;
__maybe_static void initialize_fake_status(void) {}
static int security_context_to_sid_with_policy(void) { return 0; }
static int security_sid_to_context_with_policy(void) { return 0; }
static void security_compute_av_user_with_policy(void) {}
"""
        for declaration in ("", "static struct selinux_state fake_state;\n", "__maybe_static struct selinux_state fake_state;\n"):
            with self.subTest(declaration=declaration), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "selinux_hide.c"
                path.write_text(declaration + source, encoding="utf-8")
                patch = self.namespace["patch_bakasu_selinux_hide"]
                patch(path)
                patched = path.read_text(encoding="utf-8")
                if declaration:
                    self.assertIn("struct selinux_state fake_state;", patched)
                    self.assertNotRegex(patched, r"(?:static|__maybe_static)\s+struct selinux_state fake_state;")
                else:
                    self.assertNotIn("fake_state", patched)
                self.assertIn("bool ksu_selinux_hide_running __read_mostly = false;", patched)
                self.assertIn("int security_context_to_sid_with_policy(", patched)
                patch(path)
                self.assertEqual(patched, path.read_text(encoding="utf-8"))

                path.write_text(patched.replace("int security_sid_to_context_with_policy", "int removed_helper"), encoding="utf-8")
                with self.assertRaisesRegex(SystemExit, "security_sid_to_context_with_policy"):
                    patch(path)


if __name__ == "__main__":
    unittest.main()
