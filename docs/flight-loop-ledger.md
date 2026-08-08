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
| 4b | 2026-08-08 | (proxy-source gelezen) | Observer-DLL laadt nooit (geen eigen log). Proxy `native_observer_dinput_proxy.c`: `initialize_proxy` `failed:`→`signal_observer_failure` (`Local\MielObserverFailure-<PID>` = launcher-Failure). BOOTSTRAP_TIMEOUT=600s (niet 1s). `failure_reason` ∈ {real_dinput_*, observer_environment, observer_load, observer_initialize}. **`proxy_diagnostic` schrijft alleen via OutputDebugStringA** = onzichtbaar (= de 4× `MVP_EXC 0x40010006`), reden-string verloren. Wine-suite bouwt DINPUT.dll uit source in CI (workflow:50) → source-edit werkt. | fec568a: proxy_diagnostic + signal_failure spiegelen naar proxy-debug.log (`DIAG <reason>`) | lees DIAG-regel = exacte failing step |
| 5 | 2026-08-08 | wine 31279620443 | **ROOT CAUSE:** proxy-debug.log toont `DIAG cc_ready_initialize` → `DIAG observer_load` → `SIGNAL observer failure`. `failure_reason=observer_load` (line 137) = **`LoadLibraryA(observer_path)` gaf NULL** — de observer-hook-DLL laadt niet (Cc.dll wél ready, env-path wél gelezen). = missende dep-DLL óf DllMain returnt FALSE onder Wine. | 1f52d63: log GetLastError+path bij observer_load-fail | lees err-code (126=MOD_NOT_FOUND / 2 / 193) |
| 6 | 2026-08-08 | wine 31280198375 + GLM b83ttjclk | (pending) | — | err-code + GLM observer-DllMain/imports → fix |
| 6 | 2026-08-08 | wine 31280198375 (GetLastError) | objdump lokaal: **observer-DLL importeert `libgcc_s_sjlj-1.dll`** (GCC SJLJ EH-runtime), proxy niet. Onder Wine niet in DLL-search-path → `LoadLibraryA` faalt **ERROR_MOD_NOT_FOUND (126)**. = de ROOT CAUSE van de hele "crash". `-static-libgcc` verwijdert de import (lokaal geverifieerd, 0 libgcc). | **c27b578: `-static-libgcc` op observer-build in BEIDE workflows** | — |
| **7 (FIX)** | 2026-08-08 | wine 31280292225 + win 31280292964 | (pending) | — | observer laadt nu? suite voorbij proxy-bootstrap? bereikt scenes? |
| 7 (FIX) | 2026-08-09 | wine 31280292225 + win 31280292964(success) | **FIX WERKT.** iter-6 bevestigde `err=126`. iter-7: `DIAG observer_initialized`, GEEN failure. Checks nu TRUE: loader_init, observer_loaded/initialized, login_pending, message_loop_wake, observer_hook_loaded. **Nieuwe front:** `detail=proxy-bootstrap-timeout` (600s), `login_activation_observed=FALSE`. Observer-snapshot: application/manager=false, current_name=unresolved, manager_ticks:0, user_id:-999 → game gaat niet van login-pending→activation. | — | GLM: hoe wordt login-activation getriggerd + waarom niet headless? |
| 8 | 2026-08-09 | GLM blwxo7c6z (sterke convergentie) | **Diagnose:** application=false + manager_ticks=0 = **upstream game-stall**, main-loop start nooit → `Manager::Tick` (slot 0x0044cc14) vuurt nooit → `correlate_mode_activation` (:4531/4548, enige activation-setter, tick-gated) draait nooit → login-pending→current commit onmogelijk. Launcher's GUI-drive post alleen semantisch-lege `WM_NULL` (L:165). Game geparkeerd: (a) GetMessage/modal login-window, (b) DirectInput coop-acquire wacht op foreground-focus, of (c) WaitForSingleObject op nooit-gesignaleerd event. | GLM schrijft launcher input-drive patch (SetForegroundWindow+SetFocus+Enter-scancode 0x1c) | apply → dispatch |
| 9 | 2026-08-09 | GLM bq9xqhva2 (patch niet-converged) | GLM dumpte hook-input-functies i.p.v. launcher-diff. **Sleutel-inzicht:** `message_loop_wake_posted=TRUE` → launcher's WM_NULL-post slaagde → game **pompt messages** (heeft queue) → input-injectie levensvatbaar. Hook heeft al `send_login_submit_input` (SendInput Enter scancode 0x1c, native_observer_hook.c:3645) + `send_barn_escape_input` (SetForegroundWindow+SetFocus+SendInput) MAAR tick-gated. | GEEN dispatch (geen converged patch, 600s/run niet verspillen) | ontwerp: untimed input-injectie (hook-thread na login-pending, niet tick-gated) óf launcher-SendInput |
| 10 | (pending) | — | — | — | — |

## Volgende-stap-opties (input-injectie unblock)
Game pompt messages maar app-singleton construeert niet → wacht wsl op login-input.
- **A (hook-side, voorkeur):** observer's eigen thread roept na login_pending (zonder tick) `send_login_submit_input` aan (SendInput Enter 0x1c bestaat al) — draait in game-proces, bereikt eigen input-queue direct. Vereist plaatsing in de observer-thread-loop, niet de tick-gated pad.
- **B (launcher-side):** EnumWindows→projector-window (pid), SetForegroundWindow+SetFocus, SendInput Enter, herhaald tijdens pre-activation-wait.
- **Diagnostiek-alt:** log of GetMessage/PeekMessage draait + welke module de main-thread-IP heeft, om te bevestigen dat injectie kan landen vóór blind te proberen.
Elke run = 600s timeout bij falen → hypothese-gedreven, niet spammen.

## ROOT CAUSE (iter 1→6)
De "takeoff-climb crash" was **nooit een crash**. Keten: observer-hook-DLL
importeert `libgcc_s_sjlj-1.dll` → onder Wine niet vindbaar → `LoadLibraryA`
NULL (err 126) → proxy `signal_observer_failure` → launcher `ok=false`→exit 5
→ élk scenario aborteert in proxy-bootstrap vóór scene-logica → takeoff-climb
nooit bereikt. FEX/JIT/manager-tick/0xC0000005 waren allemaal rode haringen.
Fix = `-static-libgcc`. Verifieer met iter-7.
