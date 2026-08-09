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
| 10 | 2026-08-09 | wine 31283140548 | GLM lokaliseerde: `session_controller_thread` (native_observer_hook.c:4880) = non-tick-gated bg-thread (90000×Sleep10ms). `send_login_submit_input` (:3645) = bare SendInput Enter 0x1c, geen prereqs. Approach A gekozen. | 3846e62: controller-thread injecteert Enter (few-shot @2/5/9/15/25/40s) tot login_activation_event gesignaleerd | manager_ticks>0? activation=TRUE? scene bereikt? |
| 10 result | 2026-08-09 | — | Injectie vuurde (buiten guard) maar `login_activation_observed:false`, nog `proxy-bootstrap-timeout`, observer-log 3 regels. `login_autosubmit_sent` niet zichtbaar (emit_scheduler_watchdog diagnostics-gated, env niet gezet). Enter ontgrendelt niks → wsl app construeert nooit = geen login-UI om Enter te ontvangen; stall zit vóór login-input. | — | tijdreeks-diagnostiek |
| 11 | 2026-08-09 | wine 31283723693 | (pending) | 0b06b22: controller re-emit bootstrap-snapshot @10/30/60/120s (always-on) | construeert app? tikt manager? ooit? |
| 11 result | 2026-08-09 | — | **BESLISSEND:** 5 snapshots (0/10/30/60/120s). seq0 `application:false` → daarna `application:TRUE` (app CONSTRUEERT wél kort na bootstrap). MAAR `manager_ticks:0` bij ALLE, `current_name:unresolved`, `user_id:-999`. = **niet pre-app-stall; case B: app up, `Manager::Tick` vuurt nooit** — main-loop pompt geen ticks. Login pending, activation tick-gated → circulair tenzij login message-gedreven. Enter-injectie (iter-10) bereikte t venster niet / login vereist meer. | — | GLM: wat drijft Manager::Tick + waarom niet als app up? |
| 12 | 2026-08-09 | GLM b97kuc35i + eigen lezing :6172-6290 | **Echte auto-login-sequentie ontrafeld:** `dispatch_native_capture_login_on_manager_tick`(:6239) doet (1) `dispatch_ci_session`(:6172) = schrijf profiel **"MVO_CI"** naar `current+0xd5`(naam)/`+0x1d8`(len=6)/`+0xd4`(editing=1), DAN (2) `send_login_submit_input` (Enter). **Iter-10 stuurde Enter ZONDER profiel-write → faalde.** Crux-deadlock: `login_dispatch_ready`(:6203) vereist login als CURRENT mode (`current==login && pending==0`); wij hebben pending==mode_login, current!=login. Pending→current-commit gebeurt via tick (`correlate_mode_activation`) → tick vereist main-loop → kip-ei headless. Mogelijk tikt de FLIGHT-manager pas ná login (login-screen = Director-movie met eigen loop). | — | volgende: repliceer ci_session+Enter vanuit controller-thread ZODRA login current is; of onderzoek wie pending→current commit |
| 13 | 2026-08-09 | wine 31285900011 | (pending) | 26e75bf: mode-probe (current/pending/login-ptr + is_login + manager_ticks) @10/30/60/120s vanuit controller | wordt login ooit current? of blijft pending? |
| 13 result | 2026-08-09 | — | Probe = ALLE nul (current/pending/login=0) → `late_bootstrap_manager_address` global is 0/nooit gezet op dit pad → verkeerde manager-bron. | — | probe via app+0x1ac |
| 14 | 2026-08-09 | wine 31286519649 | (pending) | 4eaa28c: probe manager via APPLICATION_GETTER()→+0x1ac (+ log app-ptr) | echte current/pending/login mode-state |
| 14 result | 2026-08-09 | — | **BESLISSEND:** `application:9782080` (non-null constant) maar **`manager:0`** (app+0x1ac=NULL) bij ALLE 0-120s. App construeert, **manager-sub-object nooit**. → stall zit VÓÓR elke mode/login, bij **manager-constructie**. Geen manager → geen tick/MODE_RESOLVE/login. Headless bouwt de app z'n manager niet (init-pad onvoltooid, of resource-afh: display/DirectDraw/sound). | — | GLM: wat construeert app+0x1ac + waarom niet headless |
| 15 | 2026-08-09 | GLM b6j0xpxal (niet-converged) + eigen tooling-lezing | GLM convergeerde niet op manager-constructie-mechanisme. Zelf gevonden: Xvfb draait `646x512x16` **rootless, GEEN wine virtual desktop**; game gebruikt DirectDraw. Hypothese: headless rootless Wine geeft DirectDraw geen echte surface → manager-constructie aborteert. | d6de92f: forceer wine virtual desktop (HKCU\Software\Wine\Explorer Desktop=Default 646x512) | wordt app+0x1ac non-null? |
| 16 | 2026-08-09 | wine 31287200239 | (pending) | — | mode-probe: manager!=0 met virtual desktop? |
| 16 result | 2026-08-09 | — | **Virtual desktop REFUTEERT display-hypothese:** `manager:0` nog steeds, geen DirectDraw-error. Manager-constructie hangt NIET op managed desktop. Goedkope hypotheses uitgeput. | — | main-thread-EIP backtrace = definitief |
| 17 | 2026-08-09 | wine 31287913862 | GLM design (deel): `stable_module_identity`(:9312) resolve-helper, geen thread-enum in observer. Zelf geschreven: Toolhelp32 thread-enum + suspend/get-Eip/resume/log per thread. | 7d75dd3: all-thread EIP+module capture @10/30/60/120s | main-thread (mullemeck.exe) EIP = exacte blokkerende call |
| 17 result | 2026-08-09 | — | Suite faalde op `wine_prefix must not already exist` — mijn iter-15 virtual-desktop `wine reg add` creëerde de prefix vroegtijdig. Geen game-logs. iter-15's manager:0 was flaky (reg-add faalde stil, desktop nooit toegepast). | 468e7c3: revert virtual-desktop | — |
| 18 | 2026-08-09 | wine 31288505457 | (pending) | — | thread-EIP: waar parkeert main-thread? |
| 18 result | 2026-08-09 | — | **DE BLOCKER GEVONDEN** (gtDirect3d-log): game loopt eeuwig op `SetDisplayMode(640x480,16/24/32)` → **DDERR_UNSUPPORTED** — rootless Wine kan display-mode niet wisselen → DirectDraw-init voltooit nooit → manager (app+0x1ac) nooit gebouwd. Thread-EIP: 2 game-threads stuck in ntdll-wait (Sleep tussen retries). Virtual-desktop-hypothese was JUIST. | 7aec0a4: virtual desktop via configure_gdi_renderer (ná wineboot, geen guard-trip) | manager!=0? tick? scene? |
| 19 | 2026-08-09 | wine 31289125037 | (pending) | — | SetDisplayMode slaagt? manager construeert? |
| 19 result | 2026-08-09 | — | Virtual-desktop reg GESCHREVEN+geverifieerd (desktop_enable/size in prefix-bootstrap.json) MAAR SetDisplayMode nog DDERR_UNSUPPORTED, manager:0. Desktop alleen niet genoeg. Verdenking: depth-mismatch (Xvfb 16-bit vs game 32/24/16) of renderer=gdi weigert mode-change, of desktop pakt niet op CreateProcess-exe. | GLM lost ddraw-headless-config op (b4qptgjia) | juiste Xvfb-line + reg-values |
| 20 | 2026-08-09 | wine 31308724995 | GLM (b4qptgjia/bmcvtveaq) convergeerde NIET op ddraw-config (3 pogingen). Zelf gevonden: `install_headless_config` schrijft `config.ini` (`fullscreen false`) naar executable.parent = **wél de game-cwd** (`--cwd`=executable.parent), dus config wordt gelezen maar stopt de SetDisplayMode-loop niet (gtSoftware doet mode-enum alsnog). | 1701be5: Xvfb 16→24-bit (+ virtual desktop al gezet) | SetDisplayMode(640x480x24) slaagt? manager!=0? |
| 20 result | 2026-08-09 | — | Xvfb 24-bit: nog DDERR_UNSUPPORTED (2 failures ipv 4), manager:0. Display-config-aanpak (virtual desktop + depth) UITGEPUT. Game blijft SetDisplayMode aanroepen ondanks config.ini fullscreen=false. | GLM: Miel.ini fullscreen-override? / ddraw SetDisplayMode-hook | — |
| 21 | 2026-08-09 | GLM ddraw-hook analyse | (pending) | — | waar beslist gtSoftware fullscreen / hoe SetDisplayMode stubben |
| 21 | 2026-08-09 | wine 31309481795 | GLM (b5r6l3vgj) dumpte game-adres-defines, geen ddraw-fix. Zelf: klassieke remedie `UseXVidMode=N` (wine sla real XVidMode/XRandR-mode-switch over → emuleer via virtual desktop). | ebe8df7: HKCU\Software\Wine\X11 Driver UseXVidMode=N | SetDisplayMode slaagt? manager!=0? |
| 21 result | 2026-08-09 | — | `UseXVidMode=N` ook geen effect. Nog DDERR_UNSUPPORTED, manager:0. **Config-display-remedies UITGEPUT** (virtual desktop, depth 24, UseXVidMode, config.ini fullscreen=false). | — | consolidatie / handoff |

## HANDOFF-STAND na iter-21 (voor gebruiker — config-weg uitgeput)
**Twee root causes gevonden deze sessie (autonome loop, 21 iters):**
1. **libgcc (GEFIXT, `-static-libgcc`):** observer-DLL importeerde `libgcc_s_sjlj-1.dll` (ontbreekt onder Wine) → observer laadde nooit (err 126). Was de 100+-iter-blocker in vorige sessies. Nu: observer laadt, app construeert.
2. **DirectDraw SetDisplayMode headless (OPEN):** gtDirect3d-log toont `SetDisplayMode(640x480,16/24/32)`→`DDERR_UNSUPPORTED`; manager (`app+0x1ac`) construeert nooit → geen tick/login/scene.

**Config-remedies geprobeerd, GEEN effect op DDERR:** wine virtual desktop (640x480), Xvfb depth 16→24, `UseXVidMode=N`, `config.ini fullscreen=false` (wordt gelezen uit game-cwd maar stopt SetDisplayMode niet).

**Mogelijke rode haring / heroverweging:** thread-EIP-capture (iter-18) toonde beide game-threads STUCK in **ntdll-waits** (thread 224 @ntdll+0xd590, 324 @ntdll+0xd800), NIET spinnend in SetDisplayMode. De DDERR kan benign zijn (game valt naar windowed via `SetResolution Windowed` = slaagt) en de échte block = een ntdll-wait op een kernel-object dat headless nooit signaleert — NIET geresolved. Volgende diagnostiek zou zijn: het wait-object van die ntdll-waits identificeren.

**Resterende opties (gebruiker beslist):**
- (a) ddraw `SetDisplayMode` vtable-hook → DD_OK forceren (geavanceerd, COM-vtable-hook in observer; IDirectDraw::SetDisplayMode ~vtable-index 21; vereist ddraw-interface-ptr — GLM convergeerde hier niet op).
- (b) ntdll-wait-object resolven (diepere thread-instrumentatie) om te bepalen of de DDERR een rode haring is.
- (c) echte display-mode-capable X (niet Xvfb) / een ddraw-shim.
- Config-weg is op; volgende stap = grotere investering (deep RE / infra).

## HANDOFF-STAND na iter-16 (voor gebruiker)
**Grote winst (blijft):** libgcc root-cause GEFIXT → observer laadt, **app construeert** (0x953200). Was 100+ iters muurvast in vorige sessies.
**Resterende blocker (precies):** game construeert Application maar **nooit het Manager-sub-object** (`app+0x1ac`=NULL over 120s) headless → geen Manager::Tick → geen mode/login/activation. Alles downstream is gevolg.
**Uitgesloten:** niet login-input (iter-10), niet pre-app-stall (app construeert, iter-11), niet managed-desktop/DirectDraw-surface (iter-16). 
**Volgende definitieve stap:** capture de game's MAIN-thread EIP (thread-enum + SuspendThread/GetThreadContext + module-resolve) → toont exact waar de main-thread parkeert tussen app- en manager-constructie = fixbare missende trigger óf harde headless-blokkerende API. Risicovolle C (suspend kan deadlocken als main-thread een lock houdt die observer nodig heeft) → GLM ontwerpt veilig patroon.
**Mogelijke uitkomst:** als t een harde headless-API-afhankelijkheid is die we niet veilig kunnen forceren, is dit een schone, goed-gekarakteriseerde grens — gebruiker beslist over echte display / diepere RE / accepteren.

## CRUX na iter-14 (herzien — dieper dan login)
De stall is NIET login/mode maar **manager-constructie**: app (0x953200) is er, maar `app+0x1ac` (manager) blijft NULL over 120s. De observer's eigen bootstrap wacht juist op deze (`calibration_bootstrap_manager_ready`: app+0x1ac!=0) → daarom manager_ticks=0, current/pending/login allemaal 0. Alles downstream (login pending→current, tick, activation) is gevolg. **Kern-vraag:** waarom construeert MulleMeck's application z'n manager niet onder headless Wine? Kandidaten: (a) manager-creatie deferred naar msg-loop/WM_CREATE die headless niet vuurt; (b) manager-init hangt af van display/DirectDraw-surface/DirectSound die headless faalt → creatie aborteert. Mogelijke **headless-limiet** — noteren als t game-state vereist die we niet veilig kunnen forceren.

## CRUX na iter-12 (voor volgende iteratie / gebruiker)
- Auto-login = **profiel-write "MVO_CI" (current+0xd4/d5/0x1d8) DAN Enter** — beide nodig, niet alleen Enter.
- Blocker: login is PENDING, niet CURRENT; commit pending→current lijkt tick-gated → kip-ei.
- Volgende hypotheses: (a) repliceer volledige ci_session+Enter vanuit non-tick controller-thread, maar eerst uitzoeken of/wanneer login `current` wordt (log current/pending mode-ptr periodiek vanuit controller); (b) als login-screen z'n eigen Director-loop heeft die WEL draait, is de manager-tick=0 verwacht en moet de unblock puur via de login-movie's input/UI; (c) mogelijk mist de pending→current commit een specifieke game-call die headless niet triggert.
- **Diepe RE, kip-ei-kern.** Grote winst blijft libgcc-fix. Pace lang (3u-ritme).

## STAND na iter-11 (crisp)
1. **Root cause libgcc GEFIXT** (observer laadt, was de 100+-iter-blocker). ✓
2. App construeert nu (application:true). ✓
3. **Open:** `Manager::Tick` vuurt nooit (manager_ticks blijft 0 over 120s) ondanks app up + message-queue (WM_NULL-post slaagde). Login pending, nooit activation.
4. Enter-injectie via SendInput mist (venster niet foreground headless). Volgende gok: PostMessage WM_KEYDOWN/UP VK_RETURN naar exacte window-handle (EnumWindows find_projector_window :2906), evt. profiel-selectie eerst.
5. Diepe RE-front — pace richting 3u-ritme.

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
