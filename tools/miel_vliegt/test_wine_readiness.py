#!/usr/bin/env python3
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import wine_readiness


DIRECTSOUND = "{47D4D946-62E8-11CF-93BC-444553540000}"
MMDEVICE = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"


class WineReadinessTests(unittest.TestCase):
    def observation(self, directory: Path) -> dict:
        logs = {
            "wineboot": "wineboot completed\n",
            "transport": "MIEL_WINE_TRANSPORT_OK\n",
            "rpcss-service": (
                "SERVICE_NAME: RpcSs\n"
                "        TYPE               : 10  WIN32_OWN_PROCESS\n"
                "        STATE              : 4  RUNNING\n"
            ),
            "process-snapshot": "wineserver64\nservices.exe\nrpcss.exe\n",
            "wineserver-shutdown": "MIEL_WINESERVER_STOPPED\n",
        }
        for clsid, dll in (
            (DIRECTSOUND, "dsound.dll"),
            (MMDEVICE, "mmdevapi.dll"),
        ):
            logs[f"com-registry:{clsid}"] = (
                f"HKEY_CLASSES_ROOT\\CLSID\\{clsid}\\InprocServer32\n"
                f"    (Default)    REG_SZ    C:\\windows\\system32\\{dll}\n"
            )
            logs[f"com-activation:{clsid}"] = (
                f"MIEL_COM_ACTIVATION clsid={clsid} hresult=0x00000000\n"
            )
        phases = []
        for identifier, text in logs.items():
            filename = hashlib.sha256(identifier.encode()).hexdigest() + ".log"
            path = directory / filename
            path.write_text(text, encoding="utf-8")
            phases.append({
                "id": identifier,
                "command": ["probe", identifier],
                "exitCode": 0,
                "timedOut": False,
                "log": {
                    "path": filename,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                },
            })
        return {
            "schema": 1,
            "protocol": wine_readiness.OBSERVATION_PROTOCOL,
            "backend": {"id": "fex", "wine": "9.0"},
            "requirements": {
                "service": "RpcSs",
                "transportSentinel": "MIEL_WINE_TRANSPORT_OK",
                "comClasses": [DIRECTSOUND, MMDEVICE],
            },
            "phases": phases,
        }

    def test_positive_service_com_process_and_shutdown_proofs_are_ready(self):
        with tempfile.TemporaryDirectory() as raw:
            receipt = wine_readiness.validate_observation(
                self.observation(Path(raw)), evidence_root=Path(raw),
            )
        self.assertEqual(receipt["status"], "READY")
        self.assertTrue(all(receipt["checks"].values()))
        self.assertFalse(receipt["exitZeroIsReadinessEvidence"])
        self.assertFalse(receipt["nativeParityEvidence"])

    def test_exit_zero_without_rpcss_and_com_activation_is_blocked(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            rpcss = next(
                row for row in observation["phases"] if row["id"] == "rpcss-service"
            )
            rpcss_path = directory / rpcss["log"]["path"]
            rpcss_path.write_text("STATE : 1 STOPPED\n", encoding="utf-8")
            rpcss["log"]["sha256"] = hashlib.sha256(rpcss_path.read_bytes()).hexdigest()
            activation = next(
                row for row in observation["phases"]
                if row["id"] == f"com-activation:{DIRECTSOUND}"
            )
            activation_path = directory / activation["log"]["path"]
            activation_path.write_text("regsvr32 succeeded\n", encoding="utf-8")
            activation["log"]["sha256"] = hashlib.sha256(
                activation_path.read_bytes()
            ).hexdigest()
            receipt = wine_readiness.validate_observation(
                observation, evidence_root=directory,
            )
        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertFalse(receipt["checks"]["rpcss_service_running"])
        self.assertFalse(receipt["checks"]["required_com_activated"])
        self.assertTrue(receipt["checks"]["wineboot_process_completed"])

    def test_rpcss_timeout_is_classified_even_when_wrapper_reports_exit_zero(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            rpcss = next(
                row for row in observation["phases"] if row["id"] == "rpcss-service"
            )
            rpcss["timedOut"] = True
            rpcss_path = directory / rpcss["log"]["path"]
            rpcss_path.write_text(
                "err:ole:start_rpcss Failed to start RpcSs service: timeout\n",
                encoding="utf-8",
            )
            rpcss["log"]["sha256"] = hashlib.sha256(rpcss_path.read_bytes()).hexdigest()
            receipt = wine_readiness.validate_observation(
                observation, evidence_root=directory,
            )
        codes = {row["code"] for row in receipt["diagnostics"]}
        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertIn("RPCSS_START_FAILED", codes)
        self.assertIn("PHASE_TIMEOUT", codes)
        self.assertFalse(receipt["checks"]["fatal_diagnostics_absent"])

    def test_log_hash_drift_and_path_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            tampered = copy.deepcopy(observation)
            tampered["phases"][0]["log"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError, "hash differs"
            ):
                wine_readiness.validate_observation(
                    tampered, evidence_root=directory,
                )
            escaped = copy.deepcopy(observation)
            escaped["phases"][0]["log"]["path"] = "../outside.log"
            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError, "escapes"
            ):
                wine_readiness.validate_observation(
                    escaped, evidence_root=directory,
                )

    def test_missing_process_snapshot_cannot_be_inferred_from_service_exit_zero(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            process = next(
                row for row in observation["phases"] if row["id"] == "process-snapshot"
            )
            process_path = directory / process["log"]["path"]
            process_path.write_text("services.exe\n", encoding="utf-8")
            process["log"]["sha256"] = hashlib.sha256(
                process_path.read_bytes()
            ).hexdigest()
            receipt = wine_readiness.validate_observation(
                observation, evidence_root=directory,
            )
        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertFalse(receipt["checks"]["service_process_topology"])


if __name__ == "__main__":
    unittest.main()
