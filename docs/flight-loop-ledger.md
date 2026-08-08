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
| 2 | 2026-08-08 | win 31276828676 / wine 31276829754 | NameError-fix werkt (suite draait door); wine-artefact werkt nu. **Nieuw front:** faalt NON-RETRYABLE op scenario-1 (controls-press-hold-release) in PROXY-bootstrap, vóór scene-logica → bereikt takeoff-climb NOOIT. Receipt: phase=proxy, detail=observer-or-login-lifecycle-failed, **start_patch_exit_code=5**, observer_loaded=FALSE, loader_initialization_completed=FALSE, main_thread_resumed=TRUE, target_terminated=TRUE, route=None. Game self-exit 5 tijdens loader/observer-bootstrap. Result-receipts (early_phase_watchdog) worden NOOIT geschreven → summary-extractor vindt 0; diagnostiek zit in failed-attempts/*/native-observer-launch-wine.json. | GLM analyseert exit-5 root-cause (bgxe27ffw) | wacht GLM → patch → dispatch iter-3 |
| 3 | 2026-08-08 | wine 31278243756 | GLM verfijnde: launcher `native_observer_launcher.c:653` krijgt van `wait_for_proxy_bootstrap` het **observer-lifecycle-FAILED event (object+1)** = proxy-DLL laadt+draait WEL maar signaleert login/observer-lifecycle-fail (niet timeout/DLL-mist). Maar artefact had 0 `.log` → MVP_*-breadcrumbs onzichtbaar. | 8c9cdc5: wine-suite kopieert nu game/proxy/orchestration/drive_c `*.log` → output/collected-logs (`-xdev`, mijdt wine-prefix EACCES) | lees collected-logs → waaróm signaleert proxy lifecycle-fail? |
| 3b | 2026-08-08 | (proxy-log gelezen) | **GEEN CRASH.** proxy-debug.log: DINPUT-proxy DllMain laadt ✓, exit-hooks ✓; `MVP_EXC 0x40010006` = DBG_PRINTEXCEPTION_C (OutputDebugString, benign) — geen 0xC0000005. Hook-install 3× = proxy in 3 processen. Launcher faalt na **1.001s** (niet 600s-timeout) = observer-lifecycle-FAILED event binnen 1s; **observer-DLL laadt nooit** (observer_loaded=false) terwijl DINPUT-proxy wel. Vermoeden: observer geïnjecteerd in verkeerd proces (projector-parent vs game-child) of fast-fail-event. | GLM analyseert (b2p7zr1ga) | patch observer-injectie/event |
| 4 | 2026-08-08 | wine 31278942022 | Launcher-logica gelezen (`native_observer_launcher.c:296-345`): failure = **named "Failure"-event direct gesignaleerd (line 308)**, alle ready/pending/activation flags false → **observer signaleert Failure vóór Ready, ~1s in init**. Observer's eigen log (`native-observer-wine.log`) staat op output.parent (.cold-capture-staging), niet in game/proxy/drive_c → nog onzichtbaar. | d5e63e7: scan nu ook OUTPUT_ROOT (prune collected-logs) | lees observer-init-log → waarom Failure? |
| 5 | (pending) | — | — | — | — |
