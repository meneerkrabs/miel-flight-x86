#!/usr/bin/env python3
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_phase_logs_must_be_bound_to_self_identifying_commands(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            for phase in observation["phases"]:
                phase["command"] = ["unrelated-diagnostic"]
            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError,
                "phase command identity differs",
            ):
                wine_readiness.validate_observation(
                    observation, evidence_root=directory,
                )

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

    def test_wineboot_exit_zero_requires_completion_record(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            wineboot = next(
                row for row in observation["phases"]
                if row["id"] == "wineboot"
            )
            wineboot_path = directory / wineboot["log"]["path"]
            wineboot_path.write_text("wrapper exited 0\n", encoding="utf-8")
            wineboot["log"]["sha256"] = hashlib.sha256(
                wineboot_path.read_bytes()
            ).hexdigest()
            receipt = wine_readiness.validate_observation(
                observation, evidence_root=directory,
            )

        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertFalse(receipt["checks"]["wineboot_process_completed"])

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

    def test_rpcss_running_state_must_be_in_the_same_service_record(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            rpcss = next(
                row for row in observation["phases"]
                if row["id"] == "rpcss-service"
            )
            rpcss_path = directory / rpcss["log"]["path"]
            rpcss_path.write_text(
                "SERVICE_NAME        :  RpcSs\n"
                "        TYPE               : 10  WIN32_OWN_PROCESS\n"
                "        STATE              : 1  STOPPED\n"
                "\n"
                "SERVICE_NAME        :  unrelated\n"
                "        TYPE               : 10  WIN32_OWN_PROCESS\n"
                "        STATE              : 4  RUNNING\n",
                encoding="utf-8",
            )
            rpcss["log"]["sha256"] = hashlib.sha256(
                rpcss_path.read_bytes()
            ).hexdigest()
            receipt = wine_readiness.validate_observation(
                observation, evidence_root=directory,
            )

        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertFalse(receipt["checks"]["rpcss_service_running"])

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
            absolute = copy.deepcopy(observation)
            absolute["phases"][0]["log"]["path"] = str(
                directory / absolute["phases"][0]["log"]["path"]
            )
            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError, "log path is not relative"
            ):
                wine_readiness.validate_observation(
                    absolute, evidence_root=directory,
                )

            linked = copy.deepcopy(observation)
            original = directory / linked["phases"][0]["log"]["path"]
            alias = directory / "phase-alias.log"
            alias.symlink_to(original)
            linked["phases"][0]["log"]["path"] = alias.name
            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError, "log path is a symlink"
            ):
                wine_readiness.validate_observation(
                    linked, evidence_root=directory,
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

    def test_registry_path_and_dll_value_must_be_in_the_same_readback_record(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            registry = next(
                row for row in observation["phases"]
                if row["id"] == f"com-registry:{DIRECTSOUND}"
            )
            registry_path = directory / registry["log"]["path"]
            registry_path.write_text(
                f"HKEY_CLASSES_ROOT\\CLSID\\{DIRECTSOUND}\\InprocServer32\n"
                "unrelated diagnostic line\n"
                "unrelated line REG_SZ C:\\windows\\system32\\dsound.dll\n",
                encoding="utf-8",
            )
            registry["log"]["sha256"] = hashlib.sha256(
                registry_path.read_bytes()
            ).hexdigest()
            receipt = wine_readiness.validate_observation(
                observation, evidence_root=directory,
            )

        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertFalse(receipt["checks"]["required_com_registered"])
        self.assertFalse(
            receipt["com"]["registry"][DIRECTSOUND]
        )

    def test_registry_record_must_use_the_exact_key_and_default_value(self):
        valid_value = (
            "    (Default)    REG_SZ    C:\\windows\\system32\\dsound.dll\n"
        )
        records = (
            (
                f"HKEY_CLASSES_ROOT\\CLSID\\{DIRECTSOUND}\\Bogus\\"
                f"CLSID\\{DIRECTSOUND}\\InprocServer32\n",
                valid_value,
            ),
            (
                f"HKEY_CLASSES_ROOT\\CLSID\\{DIRECTSOUND}\\InprocServer32\n",
                "    NamedValue    REG_SZ    C:\\windows\\system32\\dsound.dll\n",
            ),
        )
        for header, value in records:
            with self.subTest(header=header):
                with tempfile.TemporaryDirectory() as raw:
                    directory = Path(raw)
                    observation = self.observation(directory)
                    registry = next(
                        row for row in observation["phases"]
                        if row["id"] == f"com-registry:{DIRECTSOUND}"
                    )
                    registry_path = directory / registry["log"]["path"]
                    registry_path.write_text(header + value, encoding="utf-8")
                    registry["log"]["sha256"] = hashlib.sha256(
                        registry_path.read_bytes()
                    ).hexdigest()
                    receipt = wine_readiness.validate_observation(
                        observation, evidence_root=directory,
                    )

                self.assertEqual(receipt["status"], "BLOCKED")
                self.assertFalse(
                    receipt["com"]["registry"][DIRECTSOUND]
                )

    def test_registry_class_must_resolve_its_reviewed_dll(self):
        for dll in ("mmdevapi.dll", "unrelated.dll"):
            with self.subTest(dll=dll):
                with tempfile.TemporaryDirectory() as raw:
                    directory = Path(raw)
                    observation = self.observation(directory)
                    registry = next(
                        row for row in observation["phases"]
                        if row["id"] == f"com-registry:{DIRECTSOUND}"
                    )
                    registry_path = directory / registry["log"]["path"]
                    registry_path.write_text(
                        f"HKEY_CLASSES_ROOT\\CLSID\\{DIRECTSOUND}"
                        "\\InprocServer32\n"
                        f"    (Default)    REG_SZ    C:\\windows\\system32\\{dll}\n",
                        encoding="utf-8",
                    )
                    registry["log"]["sha256"] = hashlib.sha256(
                        registry_path.read_bytes()
                    ).hexdigest()
                    receipt = wine_readiness.validate_observation(
                        observation, evidence_root=directory,
                    )

                self.assertEqual(receipt["status"], "BLOCKED")
                self.assertFalse(receipt["checks"]["required_com_registered"])
                self.assertFalse(receipt["com"]["registry"][DIRECTSOUND])

    def test_com_activation_sentinel_must_be_a_standalone_record(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            activation = next(
                row for row in observation["phases"]
                if row["id"] == f"com-activation:{DIRECTSOUND}"
            )
            activation_path = directory / activation["log"]["path"]
            activation_path.write_text(
                "diagnostic considered "
                f"MIEL_COM_ACTIVATION clsid={DIRECTSOUND} "
                "hresult=0x00000000 but did not emit the record\n",
                encoding="utf-8",
            )
            activation["log"]["sha256"] = hashlib.sha256(
                activation_path.read_bytes()
            ).hexdigest()
            receipt = wine_readiness.validate_observation(
                observation, evidence_root=directory,
            )

        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertFalse(receipt["checks"]["required_com_activated"])
        self.assertFalse(
            receipt["com"]["activation"][DIRECTSOUND]
        )

    def test_transport_and_shutdown_sentinels_must_be_standalone_lines(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            for phase_id, prose in (
                (
                    "transport",
                    "diagnostic considered but did not emit "
                    "MIEL_WINE_TRANSPORT_OK here\n",
                ),
                (
                    "wineserver-shutdown",
                    "cleanup note mentions MIEL_WINESERVER_STOPPED "
                    "but it is not the record\n",
                ),
            ):
                phase = next(
                    row for row in observation["phases"]
                    if row["id"] == phase_id
                )
                phase_path = directory / phase["log"]["path"]
                phase_path.write_text(prose, encoding="utf-8")
                phase["log"]["sha256"] = hashlib.sha256(
                    phase_path.read_bytes()
                ).hexdigest()
            receipt = wine_readiness.validate_observation(
                observation, evidence_root=directory,
            )

        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertFalse(receipt["checks"]["transport_roundtrip"])
        self.assertFalse(receipt["checks"]["wineserver_clean_shutdown"])

    def test_transport_sentinel_identity_is_protocol_fixed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            observation["requirements"]["transportSentinel"] = (
                "wineboot completed"
            )
            transport = next(
                row for row in observation["phases"]
                if row["id"] == "transport"
            )
            transport_path = directory / transport["log"]["path"]
            transport_path.write_text("wineboot completed\n", encoding="utf-8")
            transport["log"]["sha256"] = hashlib.sha256(
                transport_path.read_bytes()
            ).hexdigest()

            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError,
                "requirements are invalid",
            ):
                wine_readiness.validate_observation(
                    observation, evidence_root=directory,
                )

    def test_com_class_inventory_is_protocol_fixed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            observation["requirements"]["comClasses"] = [DIRECTSOUND]
            observation["phases"] = [
                row for row in observation["phases"]
                if not row["id"].endswith(MMDEVICE)
            ]

            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError,
                "COM-class inventory is invalid",
            ):
                wine_readiness.validate_observation(
                    observation, evidence_root=directory,
                )

    def test_process_topology_requires_distinct_process_records(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            process = next(
                row for row in observation["phases"]
                if row["id"] == "process-snapshot"
            )
            process_path = directory / process["log"]["path"]
            process_path.write_text(
                "diagnostic expected wineserver, services.exe, and "
                "rpcss.exe, but no snapshot was taken\n",
                encoding="utf-8",
            )
            process["log"]["sha256"] = hashlib.sha256(
                process_path.read_bytes()
            ).hexdigest()
            receipt = wine_readiness.validate_observation(
                observation, evidence_root=directory,
            )

        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertFalse(receipt["checks"]["service_process_topology"])

    def test_process_topology_requires_standalone_process_records(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            process = next(
                row for row in observation["phases"]
                if row["id"] == "process-snapshot"
            )
            process_path = directory / process["log"]["path"]
            process_path.write_text(
                "diagnostic expected wineserver64\n"
                "unrelated services.exe mention\n"
                "maybe rpcss.exe\n",
                encoding="utf-8",
            )
            process["log"]["sha256"] = hashlib.sha256(
                process_path.read_bytes()
            ).hexdigest()
            receipt = wine_readiness.validate_observation(
                observation, evidence_root=directory,
            )

        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertFalse(receipt["checks"]["service_process_topology"])

    def test_process_topology_requires_one_snapshot_record(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            process = next(
                row for row in observation["phases"]
                if row["id"] == "process-snapshot"
            )
            process_path = directory / process["log"]["path"]
            process_path.write_text(
                "wineserver64\n"
                "unrelated diagnostic\n"
                "services.exe\n"
                "another unrelated diagnostic\n"
                "rpcss.exe\n",
                encoding="utf-8",
            )
            process["log"]["sha256"] = hashlib.sha256(
                process_path.read_bytes()
            ).hexdigest()
            receipt = wine_readiness.validate_observation(
                observation, evidence_root=directory,
            )

        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertFalse(receipt["checks"]["service_process_topology"])

    def test_distinct_lifecycle_phases_cannot_share_one_log(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            shared_path = directory / "shared-lifecycle.log"
            shared_path.write_text(
                "MIEL_WINE_TRANSPORT_OK\nMIEL_WINESERVER_STOPPED\n",
                encoding="utf-8",
            )
            shared = {
                "path": shared_path.name,
                "sha256": hashlib.sha256(
                    shared_path.read_bytes()
                ).hexdigest(),
            }
            for phase_id in ("transport", "wineserver-shutdown"):
                phase = next(
                    row for row in observation["phases"]
                    if row["id"] == phase_id
                )
                phase["log"] = dict(shared)

            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError,
                "phase logs are shared",
            ):
                wine_readiness.validate_observation(
                    observation, evidence_root=directory,
                )

    def test_distinct_lifecycle_phases_cannot_share_one_hardlink(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            shared_path = directory / "shared-lifecycle.log"
            linked_path = directory / "hardlinked-lifecycle.log"
            shared_path.write_text(
                "MIEL_WINE_TRANSPORT_OK\nMIEL_WINESERVER_STOPPED\n",
                encoding="utf-8",
            )
            linked_path.hardlink_to(shared_path)
            digest = hashlib.sha256(shared_path.read_bytes()).hexdigest()
            for phase_id, path_name in (
                ("transport", shared_path.name),
                ("wineserver-shutdown", linked_path.name),
            ):
                phase = next(
                    row for row in observation["phases"]
                    if row["id"] == phase_id
                )
                phase["log"] = {"path": path_name, "sha256": digest}

            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError,
                "phase logs are shared",
            ):
                wine_readiness.validate_observation(
                    observation, evidence_root=directory,
                )

    def test_backend_identity_must_be_a_nonempty_string_mapping(self):
        invalid_backends = (
            None,
            [],
            {},
            {"id": ""},
            {"id": "fex"},
            {"id": 1},
            {"id": "fex", "wine": 9},
        )
        for backend in invalid_backends:
            with self.subTest(backend=backend):
                with tempfile.TemporaryDirectory() as raw:
                    directory = Path(raw)
                    observation = self.observation(directory)
                    observation["backend"] = backend
                    with self.assertRaisesRegex(
                        wine_readiness.WineReadinessError,
                        "backend identity is invalid",
                    ):
                        wine_readiness.validate_observation(
                            observation, evidence_root=directory,
                        )

    def test_duplicate_json_keys_cannot_silently_replace_readiness_fields(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            observation_path = directory / "observation.json"
            observation_path.write_text(json.dumps(observation), encoding="utf-8")
            rendered = observation_path.read_text(encoding="utf-8")
            duplicated = rendered.replace(
                '"schema": 1, ',
                '"schema": 1, "schema": 1, ',
                1,
            )
            self.assertNotEqual(rendered, duplicated)
            observation_path.write_text(duplicated, encoding="utf-8")
            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError, "duplicate JSON key"
            ):
                wine_readiness.validate_file(observation_path)

    def test_receipt_output_cannot_overwrite_bound_evidence(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            observation_path = directory / "observation.json"
            observation_path.write_text(json.dumps(observation), encoding="utf-8")
            phase_log = directory / observation["phases"][0]["log"]["path"]
            observation_bytes = observation_path.read_bytes()
            log_bytes = phase_log.read_bytes()

            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError,
                "receipt output aliases evidence",
            ):
                wine_readiness.validate_file(observation_path, phase_log)
            with self.assertRaisesRegex(
                wine_readiness.WineReadinessError,
                "receipt output aliases evidence",
            ):
                wine_readiness.validate_file(
                    observation_path, output_path=observation_path,
                )

            self.assertEqual(observation_path.read_bytes(), observation_bytes)
            self.assertEqual(phase_log.read_bytes(), log_bytes)

    def test_source_hash_binds_the_validated_observation_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            observation = self.observation(directory)
            observation_path = directory / "observation.json"
            observation_path.write_text(json.dumps(observation), encoding="utf-8")
            validated_digest = hashlib.sha256(
                observation_path.read_bytes()
            ).hexdigest()
            real_validate = wine_readiness.validate_observation

            def replace_then_validate(value, *, evidence_root):
                observation_path.write_text('{"mutated":true}', encoding="utf-8")
                return real_validate(value, evidence_root=evidence_root)

            with mock.patch.object(
                wine_readiness,
                "validate_observation",
                side_effect=replace_then_validate,
            ):
                receipt = wine_readiness.validate_file(observation_path)

        self.assertNotEqual(
            receipt["source"]["sha256"],
            hashlib.sha256(b'{"mutated":true}').hexdigest(),
        )
        self.assertEqual(receipt["source"]["sha256"], validated_digest)


if __name__ == "__main__":
    unittest.main()
