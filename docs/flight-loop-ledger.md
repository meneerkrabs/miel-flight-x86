# Flight autonomous-loop ledger

Doel: itereer de takeoff-climb (S3) native-x86 crash tot de checkpoints halen
(`rotation` tick 644, `climb-established` tick 1502 zonder 0xC0000005) OF
no-progress-plafond (6 opeenvolgende iteraties zonder nieuw signaal) → escaleer.

Autorisatie: user vroeg expliciet autonome loop (2026-08-08). gh = owner
`meneerkrabs` + `workflow`-scope → mag dispatchen + pushen in DEZE repo
(`meneerkrabs/miel-flight-x86`, PUBLIC = gratis CI). NIET in mulle-meck.

## Loop-protocol (elke wake)
1. `gh run list --limit 6 --json workflowName,status,conclusion,databaseId,createdAt`
2. Draait er iets? → reschedule ~20min, klaar.
3. Nieuwste completed run nieuwer dan laatst-geanalyseerde (zie ledger)?
   - windows-native: `gh run download <id> --name flight-logs` → lees
     `receipt-summary-*takeoff-climb*.json` (`observer_trace.record_count`,
     `navigation.early_phase_watchdog`, `phase_timestamps`, `session_state`).
   - x86-wine: `gh run download <id> --name flight-x86-results` (hele map).
4. GLM (`glmcodex exec --sandbox read-only/workspace-write`) analyseert de
   receipt + observer/crash-logs → verdict: manager_ticks, laatste session_state
   vóór freeze, crash-addr, backend-onafhankelijk? + CONCRETE volgende patch
   (native_observer_hook.c / hangover_probe.py / workflow).
5. Hoofdthread valideert patch (compile/yaml), commit, push, dispatch volgende.
6. Ledger-regel toevoegen. Reschedule ~25min.
7. Stop-conditie check.

## Kernvraag iter-1
manager_ticks/record_count = 0 op ZOWEL wine (31275657222) als native-x86
(31275656178)? → pre-manager-tick-crash is backend-onafhankelijk = game-logica,
niet runtime. Sterkste bewijs-as.

## Iteraties
| iter | dispatch | run-ids | verdict | patch | next |
|---|---|---|---|---|---|
| 1 | 2026-08-08 | win 31275656178 / wine 31275657222 | **BLOCKER gevonden:** `NameError: scenario_id` @ hangover_probe.py:1954 crasht ELKE scenario vóór receipt → 0 receipts, geen watchdog-data (win + wine beide). Wine-upload ook EACCES op wine-prefix/z:/boot/efi. | a547e28: `scenario_id`→`scene`; wine-artifact → output/ only | redispatch |
| 2 | 2026-08-08 | win 31276828676 / wine 31276829754 | (pending) | — | lees receipts na completion; kernvraag record_count==0 op beide backends? |
