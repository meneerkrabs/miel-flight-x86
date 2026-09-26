import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "tools/miel_vliegt/hangover/native_observer_launcher.c"


class NativeObserverLauncherExitDiagnosticTests(unittest.TestCase):
    def test_target_exit_detail_preserves_the_last_proven_boundary(self):
        source = LAUNCHER.read_text(encoding="utf-8")
        helper = source[
            source.index("static const char *proxy_target_exit_detail"):
            source.index("typedef struct EnvironmentSnapshot")
        ]
        self.assertEqual(
            source.count("target-exited-before-proxy-bootstrap"),
            1,
        )
        self.assertIn(
            "target-exited-after-login-pending-before-activation",
            helper,
        )
        self.assertIn(
            "target-exited-after-observer-ready-before-login-pending",
            helper,
        )
        self.assertLess(
            helper.index("login_pending_observed"),
            helper.index("proxy_observer_ready"),
        )

        main = source[source.index("int main(int argc"):]
        exit_branch = main[
            main.index("wait_for_proxy_bootstrap("):
            main.index("wait_for_observer_result(")
        ]
        self.assertIn(
            "proxy_target_exit_detail(&evidence)",
            exit_branch,
        )
        self.assertNotIn(
            '"target-exited-before-proxy-bootstrap"',
            exit_branch,
        )


if __name__ == "__main__":
    unittest.main()
