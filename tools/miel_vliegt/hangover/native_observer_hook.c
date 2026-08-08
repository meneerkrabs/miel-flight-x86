#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "native_dispatch_semantic_hook.h"
#include "native_dispatch_capture_targets.generated.h"
#include "native_observation_profiles.generated.h"
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * In-process semantic observer for the hash-pinned Dutch PE32 executable.
 *
 * Every observer callback runs on the original game thread.  The already-live
 * manager update is interposed through its vtable; flight-only code uses
 * byte-exact detours installed before mode_fly is dispatched.  Hooks preserve
 * general registers, flags, x87 and SSE state.  The trace contains selected
 * f32 bit patterns only: object pointers and raw object dumps are deliberately
 * excluded from flight-parity evidence.  The separate UDSP_ONLY lifecycle
 * channel records bounded command addresses for exact BEFORE/AFTER pairing;
 * it never promotes those diagnostics to natural-transition evidence.
 *
 * Legacy discovery channels superseded here (kept named for the static
 * harness): controls.sample.raw, physics.entry.raw, physics.leave.raw,
 * collision.entry.raw, camera.entry.raw, render.entry.raw.
 */

#define FLIGHT_TICK ((BYTE *)(ULONG_PTR)0x0041d990u)
#define LOGIN_TICK ((BYTE *)(ULONG_PTR)0x00428880u)
#define MODE_LIFECYCLE_RETURN ((BYTE *)(ULONG_PTR)0x0041dbcfu)
#define CONTROLS_PRE ((BYTE *)(ULONG_PTR)0x0041da31u)
#define CONTROLS_POST ((BYTE *)(ULONG_PTR)0x0041db7du)
#define FLIGHT_STEP_ENTRY ((BYTE *)(ULONG_PTR)0x0040e610u)
#define FLIGHT_STEP_LEAVE ((BYTE *)(ULONG_PTR)0x0040f824u)
#define COLLISION_ENTRY ((BYTE *)(ULONG_PTR)0x00410cdfu)
#define COLLISION_COMMIT ((BYTE *)(ULONG_PTR)0x00411d52u)
#define CAMERA_COMMIT ((BYTE *)(ULONG_PTR)0x0042d2d3u)
#define RENDER_FINAL ((BYTE *)(ULONG_PTR)0x0042db51u)
#define FUEL_DEPLETION ((BYTE *)(ULONG_PTR)0x0040ee14u)
#define FUEL_POST_CONSUME ((BYTE *)(ULONG_PTR)0x0040f5cbu)
#define CONTACT_SITE ((BYTE *)(ULONG_PTR)0x0041183cu)
#define DAMAGE_EFFECTIVE ((BYTE *)(ULONG_PTR)0x00411eaeu)
#define DAMAGE_POST ((BYTE *)(ULONG_PTR)0x00411ec4u)
#define DAMAGE_NONTERMINAL ((BYTE *)(ULONG_PTR)0x00411fa8u)
#define TERMINAL_CRASH ((BYTE *)(ULONG_PTR)0x0042e240u)
#define TERRAIN_RESULT_CRASH ((BYTE *)(ULONG_PTR)0x0042e2bbu)
#define TERRAIN_RESULT_RENDER ((BYTE *)(ULONG_PTR)0x0042d770u)
#define PARTICLE_EMITTER_TICK ((BYTE *)(ULONG_PTR)0x00433af0u)
#define PARTICLE_RESET ((BYTE *)(ULONG_PTR)0x00432f30u)
#define PARTICLE_PLACE ((BYTE *)(ULONG_PTR)0x00433e30u)
#define RENDER_LIST_DISPATCH ((BYTE *)(ULONG_PTR)0x00430270u)
#define AIRPLANE_PRESENTATION ((BYTE *)(ULONG_PTR)0x004106d0u)

#define MODE_RESOLVE ((BYTE *)(ULONG_PTR)0x0041e410u)
#define MODE_SET ((BYTE *)(ULONG_PTR)0x0041e450u)
#define QUEUE_MODE ((BYTE *)(ULONG_PTR)0x0041e490u)
#define FLIGHT_TARGET ((BYTE *)(ULONG_PTR)0x0042c6e0u)
#define EXHIBITION_CALLBACK ((BYTE *)(ULONG_PTR)0x0043f770u)
#define UDSP_DISPATCH ((BYTE *)(ULONG_PTR)0x0043c580u)
#define UDSP_ROOT_UPDATE ((BYTE *)(ULONG_PTR)0x0043cd20u)
#define UDSP_ROOT_START ((BYTE *)(ULONG_PTR)0x0043cd60u)
#define SCENE_DISPATCH_BARN ((BYTE *)(ULONG_PTR)0x00416940u)
#define SCENE_DISPATCH_GROUND ((BYTE *)(ULONG_PTR)0x00427210u)
#define SCENE_DISPATCH_FLIGHT ((BYTE *)(ULONG_PTR)0x0042e540u)
#define ENGINE_MODE_CALLBACK ((BYTE *)(ULONG_PTR)0x0041e1b0u)
#define ENGINE_MODE_COMMAND_ID 15u
#define ENGINE_MODE_COMMAND_NAME "engine_mode"
#define NATIVE_CAPTURE_DRIVER_BOOTSTRAP_PROFILE "NATIVE_DISPATCH_DRIVER_V2"
#define NATIVE_CAPTURE_DRIVER_BOOTSTRAP_PROFILE_SHA256 \
    "72925be976520350aec44c45861e5f0af1bcaaef0f33fe605f42d6d415c0cd68"
#define NATIVE_CAPTURE_DRIVER_SCENARIO_SHA256 \
    "1435350feab7bfe92840bc8be305f13a6daf539173674e0b1bab8553c7b9b165"
#define NATIVE_CAPTURE_DRIVER_INITIAL_USER_SHA256 \
    "7019275a9489a2d078f2cb38425f852dd2c019295e401ba4a58cbd67566555d6"
#define SESSION_LOAD ((BYTE *)(ULONG_PTR)0x0041e740u)
#define APPLICATION_GETTER ((BYTE *)(ULONG_PTR)0x00405a20u)
#define USER_GET_ID ((BYTE *)(ULONG_PTR)0x00405a30u)
#define USER_SET_ID ((BYTE *)(ULONG_PTR)0x00405a60u)
#define USER_GET_NAME ((BYTE *)(ULONG_PTR)0x00405a90u)
#define USER_SET_NAME ((BYTE *)(ULONG_PTR)0x00405ac0u)
#define LOGIN_FIND_OR_CREATE ((BYTE *)(ULONG_PTR)0x004290d0u)
#define LOGIN_CLEAR_UI ((BYTE *)(ULONG_PTR)0x004292b0u)
#define AIRPLANE_COMPLETE ((BYTE *)(ULONG_PTR)0x004102d0u)
#define BARN_FLYAWAY ((BYTE *)(ULONG_PTR)0x00419100u)
#define BARN_INPUT_DISPATCH ((BYTE *)(ULONG_PTR)0x00417160u)
#define BARN_ESCAPE_LOOKUP ((BYTE *)(ULONG_PTR)0x004175b9u)
#define BARN_ESCAPE_ACTION ((BYTE *)(ULONG_PTR)0x004175d7u)
#define MYGGHANGET_START_ENGINE_GATE ((BYTE *)(ULONG_PTR)0x0042611fu)
#define MYGGHANGET_DIRECT_DEPARTURE ((BYTE *)(ULONG_PTR)0x004262eeu)
#define FLIGHT_RENDER_LIST_REGISTRATION ((BYTE *)(ULONG_PTR)0x0041d4a9u)
#define FLIGHT_RENDER_LIST_USE ((BYTE *)(ULONG_PTR)0x0042d365u)

/* Compatibility names used by the repository's source-level smoke test. */
#define CONTROLS_SAMPLE CONTROLS_PRE
#define CAMERA_ENTRY CAMERA_COMMIT
#define RENDER_ENTRY RENDER_FINAL

#define TRACE_BUFFER_SIZE (16u * 1024u * 1024u)
#define TRACE_LINE_SIZE 1536u
#define DEFAULT_RECORD_LIMIT 100000u
#define LATE_BOOTSTRAP_RETRY_MS 100u
#define LATE_BOOTSTRAP_COMPLETION_WAIT_MS 5000u
#define MAX_RECORD_LIMIT 1000000u
#define THREAD_CONTEXT_COUNT 8u
#define PHYSICS_STACK_DEPTH 32u
#define FLIGHT_CAPTURE_SIZE 0x265u
#define INVALID_ID 0xffffffffu
#define MAX_SCENARIO_SIZE (8u * 1024u * 1024u)
#define MAX_REPLAY_TICKS 100000u
#define MAX_REPLAY_FOCUS_EVENTS 64u
#define FOCUS_TIMELINE_ARM_WAIT_MS 5000u
#define FOCUS_TIMELINE_LATE_LIMIT_NS 250000000ull
#define MAX_PARTICLE_CHILDREN 64u
#define MAX_RENDER_LIST_NODES 128u
#define DETOUR_PROTECTION_CAPACITY 128u
#define SESSION_GATE_LIMIT 20000u
#define OBSERVER_READY_WAIT_MS 60000u
#define MODE_TRANSITION_LIMIT 32u
#define MODE_NAME_SIZE 48u
#define BODY_MODE_COUNT 22u
#define BODY_PHASE_COUNT 6u
#define BODY_THREAD_CONTEXT_COUNT 8u
#define BODY_CALL_DEPTH 64u
#define BODY_ENTRY_RECORDED 0x80000000u
#define UDSP_COMMAND_COUNT 10u
#define UDSP_THREAD_CONTEXT_COUNT 8u
#define UDSP_CALL_DEPTH 64u
#define NATURAL_TRANSITION_COUNT 48u
#define NATURAL_THREAD_CONTEXT_COUNT 8u
#define NATURAL_CALLBACK_DEPTH 8u
#define SCENE_DISPATCH_THREAD_CONTEXT_COUNT 8u
#define SCENE_DISPATCH_CALL_DEPTH 64u
#define SCENE_ROOT_NAME_SIZE 96u
#define FRAME_SIZE_LIMIT (64u * 1024u * 1024u)
#define PROJECTOR_CLIENT_WIDTH 640
#define PROJECTOR_CLIENT_HEIGHT 480
#define RUNTIME_STATE_FIELD_COUNT 39u
#define REPLAY_KEY_LEFT 0x01u
#define REPLAY_KEY_RIGHT 0x02u
#define REPLAY_KEY_UP 0x04u
#define REPLAY_KEY_DOWN 0x08u
#define REPLAY_KEY_SHIFT 0x10u
#define REPLAY_KEY_CONTROL 0x20u
#define REPLAY_KEY_MASK 0x3fu
#define RAND_IAT ((void **)(ULONG_PTR)0x0044c46cu)
#define SRAND_IAT ((void **)(ULONG_PTR)0x0044c408u)
#define LOCATION_PHASE_RAND_CALLER_RVA 0x00030a8au
#define LOCATION_PHASE_RAND_COUNT 18u
/* Return RVAs immediately after the only two rand() calls in the hash-bound
 * animation functions at 0x004013e0 and 0x00401530.  Recording all global
 * rand() traffic here would make unrelated simulation RNG look like animation
 * cadence evidence. */
#define ANIMATION_RANDOMFRAME_START_CALLER_RVA 0x00000405u
#define ANIMATION_RANDOMFRAME_CADENCE_CALLER_RVA 0x000005a2u
/* Hash-bound thiscall entry points: create/start an audio instance, then poll
 * that same instance for completion. */
#define AUDIO_START ((BYTE *)(ULONG_PTR)0x00409fc0u)
#define AUDIO_POLL ((BYTE *)(ULONG_PTR)0x0040a650u)
#define MEDIA_AUDIO_INSTANCE_CAPACITY 128u
#define POSITION_CHARACTER_WRITE ((BYTE *)(ULONG_PTR)0x0043c6f6u)
#define POSITION_CHARACTER_RESOLVE ((BYTE *)(ULONG_PTR)0x0041ad50u)
#define MANAGER_RENDER_VTABLE_SLOT ((void **)(ULONG_PTR)0x0044cc10u)
#define MANAGER_TICK_VTABLE_SLOT ((void **)(ULONG_PTR)0x0044cc14u)
#define CC_SHADOW_RENDER_IAT ((void **)(ULONG_PTR)0x0044c2b4u)
#define STARTUP_MODE_ARGUMENT ((BYTE *)(ULONG_PTR)0x0041d75du)
#define NATURAL_HOOK_BUILD "native-observer-natural-v1"
#define NATURAL_EXECUTABLE_SHA256 \
    "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2"

static const BYTE EXPECTED_EXE_SHA256[32] = {
    0xa8, 0x45, 0x50, 0xb4, 0x66, 0x12, 0xdc, 0x32,
    0x61, 0x77, 0xa6, 0x7a, 0x84, 0xd6, 0xfd, 0x1e,
    0x35, 0xaa, 0xe3, 0xdc, 0x74, 0x36, 0x12, 0x54,
    0x61, 0x1d, 0x1b, 0x03, 0xed, 0xa5, 0x59, 0xa2
};
static const BYTE STARTUP_MODE_ARGUMENT_SIGNATURE[] = {
    0xb4, 0x65, 0x45, 0x00
};
static const BYTE EXPECTED_CC_SHA256[32] = {
    0xc7, 0xb0, 0x59, 0x9d, 0xe3, 0x5d, 0xb3, 0x39,
    0xc4, 0xa3, 0xac, 0xc5, 0x69, 0x87, 0xe3, 0x6c,
    0x7b, 0x07, 0xeb, 0xf3, 0x55, 0x3f, 0xb7, 0x51,
    0x1b, 0xc3, 0x1d, 0x18, 0xd6, 0x67, 0xc7, 0x0e
};
static const BYTE EXPECTED_GT_SOFTWARE_SHA256[32] = {
    0xc3, 0xce, 0xbc, 0xe3, 0x43, 0x73, 0x25, 0x59,
    0x93, 0xb2, 0x3c, 0xa5, 0x4e, 0x3f, 0x67, 0x84,
    0x87, 0xf4, 0x4a, 0x5f, 0xb7, 0xc1, 0xb9, 0xf4,
    0xa6, 0x3a, 0xa3, 0xb5, 0xd8, 0x2a, 0x9e, 0xe8
};
static const BYTE EXPECTED_CONFIG_SHA256[32] = {
    0xe0, 0xa3, 0xa1, 0x9a, 0x5b, 0x21, 0xd2, 0xca,
    0xa6, 0x78, 0x02, 0x3e, 0xd6, 0x58, 0x79, 0x35,
    0xf2, 0x67, 0x22, 0xf9, 0xa4, 0x3d, 0xe5, 0xd4,
    0x76, 0x3c, 0x6d, 0x68, 0x50, 0x32, 0xca, 0x65
};

/* Exact mode registry for NL MulleMeck.exe a84550... .  BODY navigation is
 * intentionally closed to this hash-bound set instead of accepting arbitrary
 * strings from the environment. */
static const char *const BODY_MODE_ALLOWLIST[BODY_MODE_COUNT] = {
    "mode_atleartillerist", "mode_barn", "mode_brejtonbord",
    "mode_credits", "mode_dorisdigital", "mode_ernsteremit",
    "mode_fionafalk", "mode_fly", "mode_gabriellagourmet",
    "mode_grottegrundlig", "mode_login", "mode_mygghanget",
    "mode_raymondrajser", "mode_richardrevers", "mode_roymccoy",
    "mode_samposanna", "mode_samscribbler", "mode_turetapp",
    "mode_varldsutstallning", "mode_vermontvrak",
    "mode_victorvulcan", "mode_violawallmark"
};

static const BYTE TICK_SIGNATURE[] = {
    0x51, 0x56, 0x8b, 0xf1, 0x8b, 0x4e, 0x58
};
static const BYTE LOGIN_TICK_SIGNATURE[] = {
    0x51, 0xd9, 0x44, 0x24, 0x08
};
static const BYTE AUDIO_START_SIGNATURE[] = {
    0x64, 0xa1, 0x00, 0x00, 0x00, 0x00
};
static const BYTE AUDIO_POLL_SIGNATURE[] = {
    0x51, 0x56, 0x8b, 0xf1, 0x8a, 0x46, 0x1c
};
/* NL MulleMeck.exe a84550... only.  Do not reuse this VA/signature for an
 * edition whose full executable identity has not been established. */
static const BYTE MODE_SET_SIGNATURE[] = {
    0x56, 0x8b, 0xf1, 0x57, 0x8b, 0x7c, 0x24, 0x0c,
    0x8b, 0x8e, 0x8c, 0x01, 0x00, 0x00, 0x85, 0xc9
};
static const BYTE QUEUE_MODE_SIGNATURE[] = {
    0x8b, 0x44, 0x24, 0x04, 0x89, 0x81, 0x90, 0x01, 0x00, 0x00
};
static const BYTE FLIGHT_TARGET_SIGNATURE[] = {
    0x8b, 0x44, 0x24, 0x04, 0x56, 0x85, 0xc0
};
static const BYTE EXHIBITION_CALLBACK_SIGNATURE[] = {
    0x8b, 0x44, 0x24, 0x04, 0x56, 0x8b, 0xf1
};
static const BYTE UDSP_DISPATCH_SIGNATURE[] = {
    0x83, 0xec, 0x08, 0x53, 0x55, 0x56
};
static const BYTE POSITION_CHARACTER_WRITE_SIGNATURE[] = {
    0xd9, 0x46, 0x3c, 0xd9, 0x18, 0xd9, 0x58, 0x04
};
static const BYTE POSITION_CHARACTER_RESOLVE_SIGNATURE[] = {
    0x83, 0xec, 0x10, 0x56, 0x8b, 0xf1, 0xc7, 0x44,
    0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x44
};
static const BYTE UDSP_ROOT_UPDATE_SIGNATURE[] = {
    0x56, 0x8b, 0xf1, 0x8a, 0x46, 0x28
};
static const BYTE UDSP_ROOT_START_SIGNATURE[] = {
    0x56, 0x8b, 0xf1, 0x8b, 0x06, 0xff, 0x50, 0x04
};
static const BYTE SCENE_DISPATCH_BARN_SIGNATURE[] = {
    0x56, 0x8b, 0xf1, 0x57, 0x33, 0xff,
    0x8b, 0x86, 0xec, 0x1a, 0x00, 0x00
};
static const BYTE SCENE_DISPATCH_GROUND_SIGNATURE[] = {
    0x56, 0x8b, 0xf1, 0x6a, 0x0c,
    0xe8, 0x6a, 0x14, 0x02, 0x00
};
static const BYTE SCENE_DISPATCH_FLIGHT_SIGNATURE[] = {
    0x8b, 0x44, 0x24, 0x04, 0x85, 0xc0,
    0x89, 0x81, 0xc0, 0x3f, 0x00, 0x00
};
static const BYTE CONTROLS_PRE_SIGNATURE[] = {
    0x8b, 0x4e, 0x4c, 0x85, 0xc9
};
static const BYTE CONTROLS_POST_SIGNATURE[] = {
    0x8b, 0x8e, 0x84, 0x00, 0x00, 0x00
};
static const BYTE ENTRY_SIGNATURE[] = {
    0x83, 0xec, 0x60, 0x56, 0x8b, 0xf1
};
static const BYTE LEAVE_SIGNATURE[] = {
    0x8b, 0x0d, 0xe4, 0xee, 0x45, 0x00
};
static const BYTE COLLISION_SIGNATURE[] = {
    0xd9, 0x84, 0x24, 0xa8, 0x01, 0x00, 0x00
};
static const BYTE COLLISION_COMMIT_SIGNATURE[] = {
    0x8b, 0x8c, 0x24, 0xc0, 0x00, 0x00, 0x00
};
static const BYTE CAMERA_COMMIT_SIGNATURE[] = {
    0x8b, 0x8d, 0xb8, 0x00, 0x00, 0x00
};
static const BYTE RENDER_FINAL_SIGNATURE[] = {
    0x8b, 0x0d, 0x08, 0xf3, 0x45, 0x00
};
static const BYTE MODE_LIFECYCLE_SIGNATURE[] = {
    0x8b, 0x8e, 0x84, 0x00, 0x00, 0x00
};
static const BYTE PARTICLE_EMITTER_TICK_SIGNATURE[] = {
    0x83, 0xec, 0x48, 0x56, 0x8b, 0xf1
};
static const BYTE PARTICLE_RESET_SIGNATURE[] = {
    0x51, 0x56, 0x57, 0x8b, 0x3d, 0x6c, 0xc4, 0x44, 0x00
};
static const BYTE PARTICLE_PLACE_SIGNATURE[] = {
    0x55, 0x8b, 0x6c, 0x24, 0x08, 0x56, 0x8b, 0xf1
};
static const BYTE RENDER_LIST_DISPATCH_SIGNATURE[] = {
    0x56, 0x8b, 0x31, 0x85, 0xf6
};
static const BYTE AIRPLANE_PRESENTATION_SIGNATURE[] = {
    0x81, 0xec, 0xc8, 0x00, 0x00, 0x00
};
/* Cc.dll c7b059... export ?Render@CcCamera@@QAEX_N@Z, RVA 0x1d720. */
static const BYTE SHADOW_CAMERA_RENDER_SIGNATURE[] = {
    0x83, 0xec, 0x08, 0x53, 0x55, 0x8b, 0xe9
};
/* Cc.dll c7b059... protected RenderRoom export, RVA 0x1e390. */
static const BYTE SHADOW_RENDER_ROOM_SIGNATURE[] = {
    0x81, 0xec, 0x70, 0x02, 0x00, 0x00
};
/* Cc.dll c7b059... visible-object selector, RVA 0x1fd00. */
static const BYTE SHADOW_VISIBLE_OBJECTS_SIGNATURE[] = {
    0x83, 0xec, 0x08, 0x53, 0x55, 0x8b, 0x6c, 0x24, 0x1c
};
/* Cc.dll c7b059... object-to-polygon selector, RVA 0x1f5d0. */
static const BYTE SHADOW_VISIBLE_POLYGONS_SIGNATURE[] = {
    0x83, 0xec, 0x5c, 0x53, 0x8b, 0xd9, 0x55, 0x56,
    0x8a, 0x83, 0x58, 0x01, 0x00, 0x00
};
/* Cc.dll c7b059... actual polygon draw dispatch, RVA 0x1a740. */
static const BYTE SHADOW_POLYGON_RENDER_SIGNATURE[] = {
    0x81, 0xec, 0xa4, 0x01, 0x00, 0x00, 0x8b, 0x51,
    0x10, 0x53, 0x55, 0x56, 0x8b, 0x71, 0x0c
};
/* Cc.dll c7b059... cached world-matrix writer, RVA 0xf020. */
static const BYTE SHADOW_WORLD_RELATION_SIGNATURE[] = {
    0x83, 0xec, 0x2c, 0x53, 0x8b, 0xd9, 0x55, 0x8b,
    0x4b, 0x04, 0x8b, 0x6b, 0x1c
};
/* Cc.dll c7b059... in-place Z rotation writer, RVA 0x2cec0. */
static const BYTE SHADOW_ROTATION_SETTER_SIGNATURE[] = {
    0xd9, 0x44, 0x24, 0x04, 0xd9, 0xff, 0xd9, 0x44,
    0x24, 0x04
};
static const BYTE BARN_FLYAWAY_SIGNATURE[] = {
    0x56, 0x8b, 0xf1, 0xe8, 0x28, 0xf9, 0xff, 0xff
};
static const BYTE BARN_INPUT_DISPATCH_SIGNATURE[] = {
    0x64, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x6a, 0xff,
    0x68, 0xdb, 0x94, 0x44, 0x00, 0x50
};
static const BYTE BARN_ESCAPE_LOOKUP_SIGNATURE[] = {
    0x8b, 0x45, 0x10, 0x48, 0x3d, 0xcf, 0x00, 0x00,
    0x00, 0x0f, 0x87, 0xfc, 0x00, 0x00, 0x00, 0x33,
    0xd2, 0x8a, 0x90, 0xfc, 0x76, 0x41, 0x00, 0xff,
    0x24, 0x95, 0xe4, 0x76, 0x41, 0x00
};
static const BYTE BARN_ESCAPE_ACTION_SIGNATURE[] = {
    0x8b, 0x86, 0x90, 0x01, 0x00, 0x00, 0x83, 0xe8,
    0x00, 0x74, 0x32
};
static const BYTE MYGGHANGET_START_ENGINE_GATE_SIGNATURE[] = {
    0x8b, 0x46, 0x5c, 0xd9, 0x80, 0x48, 0x01, 0x00,
    0x00, 0xd8, 0x1d, 0x48, 0xc7, 0x44, 0x00
};
static const BYTE MYGGHANGET_DIRECT_DEPARTURE_SIGNATURE[] = {
    0xe8, 0x5d, 0x81, 0xff, 0xff
};
static const BYTE FLIGHT_RENDER_LIST_REGISTRATION_SIGNATURE[] = {
    0x8b, 0x40, 0x68, 0x8b, 0xce, 0x88, 0x5c, 0x24,
    0x20, 0x89, 0x86, 0x74, 0x01, 0x00, 0x00
};
static const BYTE FLIGHT_RENDER_LIST_USE_SIGNATURE[] = {
    0x8b, 0x45, 0x54, 0x8b, 0x88, 0x74, 0x01, 0x00,
    0x00, 0x3b, 0xcb, 0x74, 0x1f
};
static const BYTE FUEL_DEPLETION_SIGNATURE[] = {
    0xe8, 0x07, 0x6c, 0xff, 0xff
};
static const BYTE FUEL_POST_CONSUME_SIGNATURE[] = {
    0x8a, 0x86, 0x3b, 0x01, 0x00, 0x00
};
static const BYTE CONTACT_SIGNATURE[] = {
    0x8d, 0x4c, 0x24, 0x74, 0xff, 0x15, 0xe4, 0xc1, 0x44, 0x00
};
static const BYTE DAMAGE_EFFECTIVE_SIGNATURE[] = {
    0xd9, 0x86, 0xa0, 0x01, 0x00, 0x00
};
static const BYTE DAMAGE_POST_SIGNATURE[] = {
    0xd8, 0x1d, 0x60, 0xc5, 0x44, 0x00
};
static const BYTE DAMAGE_NONTERMINAL_SIGNATURE[] = {
    0x8b, 0x54, 0x24, 0x0c, 0x8b, 0x01
};
static const BYTE TERMINAL_CRASH_SIGNATURE[] = {
    0x53, 0x56, 0x8b, 0xf1, 0x33, 0xdb
};
static const BYTE TERRAIN_RESULT_CRASH_SIGNATURE[] = {
    0x8b, 0xc8, 0x83, 0xf9, 0x07
};
static const BYTE TERRAIN_RESULT_RENDER_SIGNATURE[] = {
    0x8b, 0x8c, 0x86, 0x2c, 0x48, 0x00, 0x00
};

typedef struct FlightObservation {
    DWORD position[3];
    DWORD orientation_wxyz[4];
    DWORD velocity[3];
    DWORD angular_velocity[3];
    DWORD propulsion;
    DWORD propulsion_scale;
    DWORD horizontal_control;
    DWORD vertical_control;
    DWORD fuel;
    DWORD integrity;
    DWORD maximum_integrity;
    DWORD pending_damage;
    DWORD damage_gate_timer;
    BYTE controls_enabled;
    BYTE floor_enabled;
    BYTE inactive;
    BYTE active;
} FlightObservation;

typedef struct ReplayTick {
    DWORD tick;
    DWORD dt_f32_bits;
    BYTE keys;
    BYTE focus_active;
} ReplayTick;

typedef struct ReplayFocusEvent {
    DWORD ordinal;
    DWORD episode;
    DWORD tick;
    BYTE active;
    ULONGLONG offset_ns;
} ReplayFocusEvent;

typedef struct RuntimeStateField {
    const char *name;
    DWORD offset;
    BYTE width;
    BOOL writable;
} RuntimeStateField;

static const RuntimeStateField RUNTIME_STATE_FIELDS[RUNTIME_STATE_FIELD_COUNT] = {
    {"active", 0x15u, 1u, FALSE},
    {"position_x", 0x70u, 4u, FALSE}, {"position_y", 0x74u, 4u, FALSE},
    {"position_z", 0x78u, 4u, FALSE}, {"orientation_w", 0x7cu, 4u, FALSE},
    {"orientation_x", 0x80u, 4u, FALSE}, {"orientation_y", 0x84u, 4u, FALSE},
    {"orientation_z", 0x88u, 4u, FALSE}, {"linear_momentum_x", 0x8cu, 4u, FALSE},
    {"linear_momentum_y", 0x90u, 4u, FALSE}, {"linear_momentum_z", 0x94u, 4u, FALSE},
    {"angular_momentum_x", 0x98u, 4u, FALSE}, {"angular_momentum_y", 0x9cu, 4u, FALSE},
    {"angular_momentum_z", 0xa0u, 4u, FALSE}, {"velocity_x", 0xecu, 4u, FALSE},
    {"velocity_y", 0xf0u, 4u, FALSE}, {"velocity_z", 0xf4u, 4u, FALSE},
    {"angular_velocity_x", 0xf8u, 4u, FALSE}, {"angular_velocity_y", 0xfcu, 4u, FALSE},
    {"angular_velocity_z", 0x100u, 4u, FALSE}, {"accumulated_force_x", 0x104u, 4u, FALSE},
    {"accumulated_force_y", 0x108u, 4u, FALSE}, {"accumulated_force_z", 0x10cu, 4u, FALSE},
    {"accumulated_torque_x", 0x110u, 4u, FALSE}, {"accumulated_torque_y", 0x114u, 4u, FALSE},
    {"accumulated_torque_z", 0x118u, 4u, FALSE}, {"pending_damage", 0x120u, 4u, FALSE},
    {"propulsion_scale", 0x164u, 4u, FALSE}, {"propulsion", 0x168u, 4u, FALSE},
    {"fuel_capacity", 0x194u, 4u, FALSE}, {"fuel", 0x198u, 4u, FALSE},
    {"integrity", 0x1a0u, 4u, FALSE}, {"maximum_integrity", 0x1a4u, 4u, FALSE},
    {"controls_enabled", 0x1c0u, 1u, FALSE}, {"horizontal_control", 0x1c4u, 4u, FALSE},
    {"vertical_control", 0x1c8u, 4u, FALSE}, {"floor_enabled", 0x1d0u, 1u, FALSE},
    {"inactive", 0x1e8u, 1u, FALSE},
    {"damage_gate_timer", 0x260u, 4u, TRUE}
};

typedef struct Sha256Context {
    DWORD state[8];
    ULONGLONG bit_count;
    BYTE block[64];
    DWORD block_used;
} Sha256Context;

typedef enum SessionState {
    SESSION_WAIT_LOGIN = 0,
    SESSION_DISPATCHED = 1,
    SESSION_ARMED = 2,
    SESSION_READY = 3,
    SESSION_COMPLETE = 4,
    SESSION_FAILED = 5
} SessionState;

typedef struct MediaAudioInstance {
    void *instance;
    DWORD call_id;
    DWORD poll_ordinal;
    BOOL complete;
    BOOL in_use;
} MediaAudioInstance;

typedef enum FlightBootstrapPhase {
    BOOTSTRAP_WAIT_BARN = 0,
    BOOTSTRAP_WAIT_MYGGHANGET_STATE_FIVE = 1,
    BOOTSTRAP_WAIT_MYGGHANGET_DEPARTURE = 2
} FlightBootstrapPhase;

typedef struct PhysicsCall {
    DWORD id;
    DWORD tick;
    DWORD frame;
    DWORD dt_f32_bits;
    DWORD flight_address;
} PhysicsCall;

typedef struct ModeTransitionObservation {
    volatile LONG state;
    DWORD id;
    DWORD manager_address;
    DWORD previous_mode;
    DWORD expected_mode;
    DWORD caller_site;
    char source_mode[MODE_NAME_SIZE];
    BOOL source_mode_valid;
    char requested_mode[MODE_NAME_SIZE];
    BOOL requested_mode_valid;
} ModeTransitionObservation;

typedef enum NaturalTransitionKind {
    NATURAL_MODE_SET = 0,
    NATURAL_FLIGHT_TARGET = 1,
    NATURAL_LOCATION_DEPARTURE = 2,
    NATURAL_QUEUE_MODE = 3
} NaturalTransitionKind;

typedef struct NaturalTransitionEdge {
    const char *id;
    const char *source_mode;
    const char *target_mode;
    DWORD site;
    NaturalTransitionKind kind;
} NaturalTransitionEdge;

typedef struct NaturalCallbackFrame {
    DWORD index;
    DWORD original_return;
} NaturalCallbackFrame;

typedef struct NaturalCallbackThread {
    volatile LONG owner_thread_id;
    DWORD depth;
    NaturalCallbackFrame frames[NATURAL_CALLBACK_DEPTH];
} NaturalCallbackThread;

typedef enum BodyDispatchState {
    BODY_DISPATCH_DISABLED = 0,
    BODY_DISPATCH_WAIT_BARN = 1,
    BODY_DISPATCH_IN_ENTRY_CALLBACK = 2,
    BODY_DISPATCH_WAIT_TARGET_ACTIVATION = 3,
    BODY_DISPATCH_WAIT_CORE = 4,
    BODY_DISPATCH_IN_RETURN_CALLBACK = 5,
    BODY_DISPATCH_WAIT_RETURN_ACTIVATION = 6,
    BODY_DISPATCH_WAIT_TEARDOWN = 7,
    BODY_DISPATCH_COMPLETE = 8,
    BODY_DISPATCH_FAILED = 9
} BodyDispatchState;

typedef struct BodyDispatchObservation {
    DWORD manager_address;
    DWORD target_address;
    DWORD return_address;
    DWORD entry_pre_current;
    DWORD entry_post_current;
    DWORD entry_post_pending;
    DWORD return_post_current;
    DWORD return_post_pending;
    DWORD callback_count;
    DWORD dispatch_thread_id;
    DWORD entry_dispatch_tick;
    DWORD target_activation_tick;
    DWORD core_ready_tick;
    DWORD return_dispatch_tick;
    DWORD return_activation_tick;
    DWORD phase_counts[BODY_PHASE_COUNT];
    DWORD last_leave_ticks[BODY_PHASE_COUNT];
} BodyDispatchObservation;

typedef enum NativeCaptureDriverState {
    NATIVE_CAPTURE_DRIVER_DISABLED = 0,
    NATIVE_CAPTURE_DRIVER_WAIT_FLIGHT_READY = 1,
    NATIVE_CAPTURE_DRIVER_IN_CALLBACK = 2,
    NATIVE_CAPTURE_DRIVER_WAIT_ACTIVATION = 3,
    NATIVE_CAPTURE_DRIVER_WAIT_CAPTURE = 4,
    NATIVE_CAPTURE_DRIVER_COMPLETE = 5,
    NATIVE_CAPTURE_DRIVER_FAILED = 6
} NativeCaptureDriverState;

typedef struct NativeCaptureDriverObservation {
    DWORD manager_address;
    DWORD target_address;
    DWORD pre_current;
    DWORD post_current;
    DWORD post_pending;
    DWORD dispatch_thread_id;
    DWORD wait_start_tick;
    DWORD flight_ready_tick;
    DWORD departure_caller_site;
    DWORD dispatch_tick;
    DWORD activation_tick;
    DWORD capture_tick;
    MvdsFinalMissionReadback before_readback;
    MvdsFinalMissionReadback hook_readback;
} NativeCaptureDriverObservation;

typedef enum BodyPhase {
    BODY_PHASE_LOAD = 0,
    BODY_PHASE_OPEN = 1,
    BODY_PHASE_TICK = 2,
    BODY_PHASE_RENDER = 3,
    BODY_PHASE_CLOSE = 4,
    BODY_PHASE_UNLOAD = 5
} BodyPhase;

typedef struct BodyModeLifecycle {
    const char *mode_id;
    const char *mode_name;
    DWORD vtable;
    DWORD constructor;
    DWORD entries[BODY_PHASE_COUNT];
} BodyModeLifecycle;

typedef struct BodyLifecycleFrame {
    const BodyModeLifecycle *mode;
    DWORD object;
    DWORD vtable;
    DWORD entry;
    DWORD return_address;
    DWORD thread;
    DWORD tick;
    DWORD depth;
    BodyPhase phase;
} BodyLifecycleFrame;

typedef struct BodyLifecycleThread {
    volatile LONG owner_thread_id;
    DWORD depth;
    BodyLifecycleFrame frames[BODY_CALL_DEPTH];
} BodyLifecycleThread;

/* Generated from content/miel_vliegt/native_mode_bodies.json and checked back
 * against that canonical hash-pinned contract by test_native_body_trace.py.
 * Phase order is LOAD, OPEN, TICK, RENDER, CLOSE, UNLOAD.  Constructors are
 * identity-only here: constructor calls cannot honestly be paired by vtable
 * interposition and therefore produce no BODY event. */
static const BodyModeLifecycle BODY_MODE_LIFECYCLES[BODY_MODE_COUNT] = {
    {"login", "mode_login", 0x0044ce88u, 0x00427a60u, {0x00427e00u, 0x00427d80u, 0x00428880u, 0x004283d0u, 0x004072e0u, 0x004282c0u}},
    {"barn", "mode_barn", 0x0044caecu, 0x00414f00u, {0x004156d0u, 0x00416180u, 0x004169a0u, 0x00416370u, 0x00416320u, 0x00416000u}},
    {"flight", "mode_fly", 0x0044cf58u, 0x0042a3a0u, {0x0042be40u, 0x0042b9a0u, 0x0042ca10u, 0x0042d6d0u, 0x0042bdc0u, 0x0042c400u}},
    {"credits", "mode_credits", 0x0044cb58u, 0x0041b410u, {0x0041b520u, 0x0041b4e0u, 0x0041b6f0u, 0x0041b7c0u, 0x0041b510u, 0x0041b680u}},
    {"roy_mccoy", "mode_roymccoy", 0x0044d828u, 0x004425a0u, {0x00442650u, 0x00425170u, 0x00440000u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"sam_scribbler", "mode_samscribbler", 0x0044d8b0u, 0x00442c30u, {0x00442ce0u, 0x00425170u, 0x00440000u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"ture_tapp", "mode_turetapp", 0x0044d8f4u, 0x00442f30u, {0x00442ff0u, 0x004434f0u, 0x00440000u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"atle_artillerist", "mode_atleartillerist", 0x0044d570u, 0x0043fd40u, {0x0043fdf0u, 0x00425170u, 0x00440000u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"viola_wallmark", "mode_violawallmark", 0x0044da28u, 0x00444c80u, {0x00444e30u, 0x00425170u, 0x004452d0u, 0x00445ce0u, 0x00445ca0u, 0x00445150u}},
    {"sampo_sanna", "mode_samposanna", 0x0044d86cu, 0x00442840u, {0x00442910u, 0x00440500u, 0x00440000u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"brejton_bord", "mode_brejtonbord", 0x0044d5b4u, 0x00440010u, {0x004400f0u, 0x00440500u, 0x00440550u, 0x00427300u, 0x00425520u, 0x00440460u}},
    {"grotte_grundlig", "mode_grottegrundlig", 0x0044d718u, 0x00441420u, {0x004414e0u, 0x004417d0u, 0x00440000u, 0x00445ce0u, 0x00425520u, 0x004417b0u}},
    {"gabriella_gourmet", "mode_gabriellagourmet", 0x0044d6d4u, 0x00441130u, {0x004411f0u, 0x00444c20u, 0x00440000u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"richard_revers", "mode_richardrevers", 0x0044d7e4u, 0x004422c0u, {0x00442370u, 0x00425170u, 0x00440000u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"victor_vulcan", "mode_victorvulcan", 0x0044d9e4u, 0x00444880u, {0x00444950u, 0x00444c20u, 0x00440000u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"varldsutstallning", "mode_varldsutstallning", 0x0044d948u, 0x00443660u, {0x00443770u, 0x00444090u, 0x00440000u, 0x004440c0u, 0x004440b0u, 0x00443c60u}},
    {"vermont_vrak", "mode_vermontvrak", 0x0044d994u, 0x004441b0u, {0x00444270u, 0x00444580u, 0x004445d0u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"fiona_falk", "mode_fionafalk", 0x0044d690u, 0x00440bd0u, {0x00440c80u, 0x00440f60u, 0x00440fa0u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"doris_digital", "mode_dorisdigital", 0x0044d608u, 0x004405c0u, {0x00440680u, 0x00425170u, 0x00440000u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"raymond_rajser", "mode_raymondrajser", 0x0044d7a0u, 0x00441c30u, {0x00441d00u, 0x00425170u, 0x00440000u, 0x00427300u, 0x00425520u, 0x00441f70u}},
    {"ernst_eremit", "mode_ernsteremit", 0x0044d64cu, 0x00440870u, {0x00440930u, 0x00425170u, 0x00440000u, 0x00427300u, 0x00425520u, 0x004259a0u}},
    {"mygghanget", "mode_mygghanget", 0x0044d75cu, 0x004418d0u, {0x004419a0u, 0x00441a60u, 0x00441b20u, 0x00427300u, 0x00425520u, 0x004259a0u}},
};

/* Exact projection of content/miel_vliegt/native_scene_transitions.json.
 * Empty source/target strings represent bootstrap/mission and terminal
 * identities; they are accepted only at their unique caller sites. */
#define NATURAL_EDGE(id, source, target, site, kind) \
    {id, source, target, site, kind}
static const NaturalTransitionEdge
NATURAL_TRANSITION_EDGES[NATURAL_TRANSITION_COUNT] = {
    NATURAL_EDGE("startup.login", "", "mode_login", 0x0041d763u, NATURAL_MODE_SET),
    NATURAL_EDGE("login.barn.keyboard", "mode_login", "mode_barn", 0x00428bb3u, NATURAL_MODE_SET),
    NATURAL_EDGE("login.barn.deferred", "mode_login", "mode_barn", 0x00429092u, NATURAL_MODE_SET),
    NATURAL_EDGE("barn.mygghanget", "mode_barn", "mode_mygghanget", 0x00419198u, NATURAL_MODE_SET),
    NATURAL_EDGE("flight.barn.crash", "mode_fly", "mode_barn", 0x0042d756u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("mygghanget.barn.state6", "mode_mygghanget", "mode_barn", 0x00441b05u, NATURAL_MODE_SET),
    NATURAL_EDGE("mygghanget.barn.offscreen", "mode_mygghanget", "mode_barn", 0x00441b67u, NATURAL_MODE_SET),
    NATURAL_EDGE("mission.mecchifinal.outro", "", "mode_varldsutstallning", 0x0041e246u, NATURAL_MODE_SET),
    NATURAL_EDGE("varldsutstallning.credits", "mode_varldsutstallning", "mode_credits", 0x0043f929u, NATURAL_MODE_SET),
    NATURAL_EDGE("varldsutstallning.barn.callback", "mode_varldsutstallning", "mode_barn", 0x0043f8fcu, NATURAL_MODE_SET),
    NATURAL_EDGE("varldsutstallning.barn.state5", "mode_varldsutstallning", "mode_barn", 0x0044404du, NATURAL_MODE_SET),
    NATURAL_EDGE("credits.terminal", "mode_credits", "", 0x0041b793u, NATURAL_QUEUE_MODE),
    NATURAL_EDGE("location.landing.mode_roymccoy", "mode_fly", "mode_roymccoy", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_roymccoy", "mode_roymccoy", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_samscribbler", "mode_fly", "mode_samscribbler", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_samscribbler", "mode_samscribbler", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_turetapp", "mode_fly", "mode_turetapp", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_turetapp", "mode_turetapp", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_atleartillerist", "mode_fly", "mode_atleartillerist", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_atleartillerist", "mode_atleartillerist", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_violawallmark", "mode_fly", "mode_violawallmark", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_violawallmark", "mode_violawallmark", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_samposanna", "mode_fly", "mode_samposanna", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_samposanna", "mode_samposanna", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_brejtonbord", "mode_fly", "mode_brejtonbord", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_brejtonbord", "mode_brejtonbord", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_grottegrundlig", "mode_fly", "mode_grottegrundlig", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_grottegrundlig", "mode_grottegrundlig", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_gabriellagourmet", "mode_fly", "mode_gabriellagourmet", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_gabriellagourmet", "mode_gabriellagourmet", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_richardrevers", "mode_fly", "mode_richardrevers", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_richardrevers", "mode_richardrevers", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_victorvulcan", "mode_fly", "mode_victorvulcan", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_victorvulcan", "mode_victorvulcan", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_varldsutstallning", "mode_fly", "mode_varldsutstallning", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_varldsutstallning", "mode_varldsutstallning", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_vermontvrak", "mode_fly", "mode_vermontvrak", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_vermontvrak", "mode_vermontvrak", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_fionafalk", "mode_fly", "mode_fionafalk", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_fionafalk", "mode_fionafalk", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_dorisdigital", "mode_fly", "mode_dorisdigital", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_dorisdigital", "mode_dorisdigital", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_raymondrajser", "mode_fly", "mode_raymondrajser", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_raymondrajser", "mode_raymondrajser", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_ernsteremit", "mode_fly", "mode_ernsteremit", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_ernsteremit", "mode_ernsteremit", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
    NATURAL_EDGE("location.landing.mode_mygghanget", "mode_fly", "mode_mygghanget", 0x00430fa4u, NATURAL_FLIGHT_TARGET),
    NATURAL_EDGE("location.departure.mode_mygghanget", "mode_mygghanget", "mode_fly", 0x00425c2eu, NATURAL_LOCATION_DEPARTURE),
};
#undef NATURAL_EDGE

static const DWORD BODY_PHASE_VTABLE_OFFSETS[BODY_PHASE_COUNT] = {
    0x20u, 0x08u, 0x14u, 0x10u, 0x0cu, 0x24u
};
static const char *const BODY_PHASE_NAMES[BODY_PHASE_COUNT] = {
    "LOAD", "OPEN", "TICK", "RENDER", "CLOSE", "UNLOAD"
};

typedef struct UdspCommandClassifier {
    DWORD opcode;
    const char *name;
    DWORD parser_case;
    DWORD handler_case;
} UdspCommandClassifier;

typedef struct UdspSnapshot {
    DWORD complete;
    DWORD started;
    DWORD modifier;
    DWORD timer_f32_bits;
    DWORD context;
    DWORD next;
    DWORD callback;
    DWORD payload[5];
    DWORD parent_complete;
    DWORD parent_current;
} UdspSnapshot;

typedef struct UdspFrame {
    const UdspCommandClassifier *command;
    DWORD call_id;
    DWORD composite;
    DWORD node;
    DWORD return_address;
    DWORD thread;
    DWORD tick;
    DWORD depth;
    DWORD dt_f32_bits;
    BOOL position_write_observed;
    DWORD position_head;
    DWORD position_context;
    DWORD position_prior_x_f32_bits;
    DWORD position_prior_y_f32_bits;
    UdspSnapshot before;
} UdspFrame;

typedef struct UdspThread {
    volatile LONG owner_thread_id;
    DWORD depth;
    UdspFrame frames[UDSP_CALL_DEPTH];
} UdspThread;

typedef enum SceneDispatchRecordKind {
    SCENE_RECORD_DISPATCH = 0,
    SCENE_RECORD_ROOT_START = 1,
    SCENE_RECORD_ROOT_UPDATE = 2
} SceneDispatchRecordKind;

typedef enum SceneDispatchRoute {
    SCENE_ROUTE_NONE = 0,
    SCENE_ROUTE_GROUND = 1,
    SCENE_ROUTE_BARN = 2,
    SCENE_ROUTE_FLIGHT = 3
} SceneDispatchRoute;

typedef struct SceneDispatchSnapshot {
    BOOL valid;
    DWORD queue_0;
    DWORD queue_1;
    DWORD queue_2;
    DWORD queue_3;
    DWORD root_complete;
    DWORD root_running;
    DWORD root_current;
    DWORD root_next;
    DWORD object_vtable;
    DWORD special_0;
    DWORD special_1;
} SceneDispatchSnapshot;

typedef struct SceneDispatchFrame {
    SceneDispatchRecordKind kind;
    SceneDispatchRoute route;
    DWORD object;
    DWORD root;
    DWORD return_address;
    DWORD thread;
    DWORD tick;
    DWORD depth;
    DWORD dt_f32_bits;
    SceneDispatchSnapshot before;
} SceneDispatchFrame;

typedef struct SceneDispatchThread {
    volatile LONG owner_thread_id;
    DWORD depth;
    SceneDispatchFrame frames[SCENE_DISPATCH_CALL_DEPTH];
} SceneDispatchThread;

/* Static classifier only.  Runtime equivalence remains unproven: these rows
 * identify the ten opcodes actually present in the pinned Dutch DEF corpus. */
static const UdspCommandClassifier UDSP_COMMANDS[UDSP_COMMAND_COUNT] = {
    {1u, "PLAY_CHARACTER_SCRIPT", 0x0043d478u, 0x0043c680u},
    {3u, "PLAY_CHARACTER_ANIMATION", 0x0043d02fu, 0x0043c718u},
    {5u, "PLAY_CHARACTER_SOUND", 0x0043d1f1u, 0x0043c880u},
    {9u, "POSITION_CHARACTER", 0x0043ced1u, 0x0043c6cdu},
    {10u, "JUDGE_AIRPLANE", 0x0043cfceu, 0x0043cac1u},
    {11u, "AWARD_DIPLOMA", 0x0043cff6u, 0x0043c632u},
    {12u, "PLAY_SOUND", 0x0043d340u, 0x0043c974u},
    {13u, "PLAY_RADIO", 0x0043d3d3u, 0x0043c9d6u},
    {14u, "PLAY_MULLEBARNSOUND", 0x0043d0feu, 0x0043c8fau},
    {15u, "WAIT", 0x0043d524u, 0x0043c5c9u},
};

typedef struct ObserverThread {
    volatile LONG owner_thread_id;
    DWORD tick;
    DWORD tick_dt_f32_bits;
    DWORD controls_sample;
    DWORD controls_dt_f32_bits;
    DWORD collision_sample;
    DWORD collision_dt_f32_bits;
    DWORD damage_f32_bits;
    DWORD damage_integrity_f32_bits;
    BOOL damage_terminal;
    DWORD physics_depth;
    DWORD physics_overflow;
    PhysicsCall physics_stack[PHYSICS_STACK_DEPTH];
} ObserverThread;

typedef struct DetourProtectionRecord {
    BYTE *target;
    void **trampoline_slot;
    DWORD original_protect;
    BOOL original_protect_known;
    BOOL in_use;
} DetourProtectionRecord;

static void *manager_tick_original __attribute__((used)) =
    (void *)(ULONG_PTR)0x0041d990u;
static void *manager_render_original __attribute__((used)) =
    (void *)(ULONG_PTR)0x0041dbc0u;
static BOOL manager_tick_interposed;
static BOOL manager_render_interposed;
static BOOL bootstrap_diagnostics_enabled;
static volatile LONG observer_bootstrap_state;
static volatile LONG late_bootstrap_manager_address;
static volatile LONG calibration_manager_identity_validated;
static void *login_tick_trampoline;
static void *audio_start_trampoline;
static void *audio_poll_trampoline;
static void *mode_set_trampoline;
static void *queue_mode_trampoline;
static void *flight_target_trampoline;
static void *exhibition_callback_trampoline;
static void *udsp_dispatch_trampoline;
static void *position_character_write_trampoline;
static void *position_character_write_resume __attribute__((used)) =
    (void *)(ULONG_PTR)0x0043c6feu;
static void *udsp_root_update_trampoline;
static void *udsp_root_start_trampoline;
static void *scene_dispatch_barn_trampoline;
static void *scene_dispatch_ground_trampoline;
static void *scene_dispatch_flight_trampoline;
static void *controls_pre_trampoline;
static void *controls_post_trampoline;
static void *flight_entry_trampoline;
static void *flight_leave_trampoline;
static void *collision_entry_trampoline;
static void *collision_entry_resume __attribute__((used)) =
    (void *)(ULONG_PTR)0x00410ce6u;
static void *collision_commit_trampoline;
static void *camera_commit_trampoline;
static void *render_final_trampoline;
static void *fuel_depletion_trampoline;
static void *fuel_post_consume_trampoline;
static void *contact_trampoline;
static void *damage_effective_trampoline;
static void *damage_post_trampoline;
static void *damage_nonterminal_trampoline;
static void *terminal_crash_trampoline;
static void *terrain_result_crash_trampoline;
static void *terrain_result_render_trampoline;
static void *particle_emitter_tick_trampoline;
static void *particle_reset_trampoline;
static void *particle_place_trampoline;
static void *render_list_dispatch_trampoline;
static void *airplane_presentation_trampoline;
static BYTE *shadow_camera_render_target;
static void *shadow_camera_render_trampoline;
static BYTE *shadow_render_room_target;
static void *shadow_render_room_trampoline;
static BYTE *shadow_visible_objects_target;
static void *shadow_visible_objects_trampoline;
static BYTE *shadow_visible_polygons_target;
static void *shadow_visible_polygons_trampoline;
static BYTE *shadow_polygon_render_target;
static void *shadow_polygon_render_trampoline;
static BYTE *shadow_world_relation_target;
static void *shadow_world_relation_trampoline;
static BYTE *shadow_rotation_setter_target;
static void *shadow_rotation_setter_trampoline;
static void *shadow_render_original __attribute__((used));
static BOOL shadow_render_interposed;
static BYTE *diagnostic_skip_target;
static BOOL diagnostic_session_only;
static BOOL diagnostic_direct_login_tick;
static BOOL diagnostic_skip_manager_tick;
static BOOL semantic_observation_only;
static BOOL scenario_bounded_observation;
static BOOL calibration_observation_only;
#define OBSERVE_OMIT_PARTICLE_EMITTER (1u << 0)
#define OBSERVE_OMIT_PARTICLE_RESET (1u << 1)
#define OBSERVE_OMIT_PARTICLE_PLACE (1u << 2)
#define OBSERVE_OMIT_RENDER_LIST (1u << 3)
#define OBSERVE_OMIT_AIRPLANE_PRESENTATION (1u << 4)
#define OBSERVE_OMIT_SHADOW_CAMERA (1u << 5)
#define OBSERVE_OMIT_SHADOW_ROOM (1u << 6)
#define OBSERVE_OMIT_SHADOW_OBJECTS (1u << 7)
#define OBSERVE_OMIT_SHADOW_POLYGONS (1u << 8)
#define OBSERVE_OMIT_SHADOW_POLYGON_RENDER (1u << 9)
#define OBSERVE_OMIT_SHADOW_WORLD_RELATION (1u << 10)
#define OBSERVE_OMIT_SHADOW_ROTATION (1u << 11)
#define OBSERVE_OMIT_SHADOW_IAT (1u << 12)
#define OBSERVE_OMIT_AIRPLANE_SHADOW_FAMILY \
    (OBSERVE_OMIT_AIRPLANE_PRESENTATION | OBSERVE_OMIT_SHADOW_CAMERA | \
     OBSERVE_OMIT_SHADOW_ROOM | \
     OBSERVE_OMIT_SHADOW_OBJECTS | OBSERVE_OMIT_SHADOW_POLYGONS | \
     OBSERVE_OMIT_SHADOW_POLYGON_RENDER | \
     OBSERVE_OMIT_SHADOW_WORLD_RELATION | OBSERVE_OMIT_SHADOW_ROTATION | \
     OBSERVE_OMIT_SHADOW_IAT)
#define OBSERVE_OMIT_SEMANTIC_DEFAULT \
    (OBSERVE_OMIT_PARTICLE_EMITTER | OBSERVE_OMIT_PARTICLE_RESET | \
     OBSERVE_OMIT_PARTICLE_PLACE | OBSERVE_OMIT_RENDER_LIST)
#define OBSERVE_OMIT_ALL ((1u << 13) - 1u)
static DWORD semantic_observation_omit_mask;
static volatile LONG body_dispatch_state = BODY_DISPATCH_DISABLED;
static volatile LONG body_callback_active;
static volatile LONG body_sequence_number;
static DWORD body_lifecycle_installed_slots;
static char body_mode_name[MODE_NAME_SIZE];
static char body_receipt_path[MAX_PATH * 2];
static BOOL body_position_probe_enabled;
static DWORD body_position_probe_start_tick = INVALID_ID;
static volatile LONG position_character_record_count;
static BodyDispatchObservation body_dispatch;
static volatile LONG native_capture_driver_state =
    NATIVE_CAPTURE_DRIVER_DISABLED;
static NativeCaptureDriverObservation native_capture_driver;
static char native_capture_driver_receipt_path[MAX_PATH * 2];
static BOOL native_capture_driver_bootstrap_requested;
static BodyLifecycleThread body_lifecycle_threads[BODY_THREAD_CONTEXT_COUNT];
static DWORD body_lifecycle_counts[BODY_MODE_COUNT][BODY_PHASE_COUNT];
static DWORD body_lifecycle_last_leave_ticks[BODY_MODE_COUNT][BODY_PHASE_COUNT];
static UdspThread udsp_threads[UDSP_THREAD_CONTEXT_COUNT];
static SceneDispatchThread
    scene_dispatch_threads[SCENE_DISPATCH_THREAD_CONTEXT_COUNT];
static BOOL scene_dispatch_observation_enabled;
static NaturalCallbackThread
    natural_callback_threads[NATURAL_THREAD_CONTEXT_COUNT];
static const NaturalTransitionEdge *natural_capture_edge;
static volatile LONG natural_transition_emitted;
static volatile LONG natural_sequence_number = 1;
static volatile LONG natural_session_started;
static volatile LONG natural_session_completed;
static volatile LONG flight_target_sequence_number;
static volatile LONG post_natural_edge_input_suspended;
static volatile LONG post_natural_edge_input_boundary_state;
static char natural_observer_sha256[65];

__declspec(dllexport) DWORD WINAPI MielObserverInitialize(LPVOID unused);
static void emit_natural_session(const char *phase, const char *result);
static void body_dispatch_fail(const char *reason);
static void __attribute__((naked)) exhibition_callback_leave_hook(void);
static BOOL dispatch_ci_session(DWORD manager_address);
static BOOL login_dispatch_ready(DWORD manager_address);
static BOOL dispatch_native_capture_login_on_manager_tick(
    DWORD manager_address);

#define RESUME_POINTER(name, address) \
    static void *name##_resume __attribute__((used)) = \
        (void *)(ULONG_PTR)(address)
RESUME_POINTER(controls_pre, 0x0041da36u);
RESUME_POINTER(controls_post, 0x0041db83u);
RESUME_POINTER(flight_entry, 0x0040e616u);
RESUME_POINTER(flight_leave, 0x0040f82au);
RESUME_POINTER(collision_commit, 0x00411d59u);
RESUME_POINTER(camera_commit, 0x0042d2d9u);
RESUME_POINTER(render_final, 0x0042db57u);
RESUME_POINTER(fuel_depletion, 0x0040ee19u);
RESUME_POINTER(fuel_post_consume, 0x0040f5d1u);
RESUME_POINTER(contact, 0x00411846u);
RESUME_POINTER(damage_effective, 0x00411eb4u);
RESUME_POINTER(damage_post, 0x00411ecau);
RESUME_POINTER(damage_nonterminal, 0x00411faeu);
RESUME_POINTER(terminal_crash, 0x0042e246u);
RESUME_POINTER(terrain_result_crash, 0x0042e2c0u);
RESUME_POINTER(terrain_result_render, 0x0042d777u);
#undef RESUME_POINTER

static HANDLE trace_file = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION trace_lock;
static BOOL trace_lock_ready;
static PVOID diagnostic_exception_handler;
static char trace_buffer[TRACE_BUFFER_SIZE];
static DWORD trace_buffer_used;
static DWORD trace_record_count;
static DWORD trace_record_limit = DEFAULT_RECORD_LIMIT;
static BOOL trace_saturated;
static BOOL trace_write_failed;
static volatile LONG initialization_started;

static volatile LONG sequence_number;
static volatile LONG diagnostic_sequence_number;
static volatile LONG media_semantics_sequence_number;
static volatile LONG media_audio_call_number;
static volatile LONG media_animation_rng_number;
static volatile LONG media_semantics_thread_id;
static volatile LONG controls_number;
static volatile LONG physics_number;
static volatile LONG collision_number;
static volatile LONG frame_number;
static volatile LONG mode_transition_number;
static volatile LONG mode_transition_sequence_number;
static volatile LONG particle_sequence_number;
static volatile LONG particle_tick_call_number;
static volatile LONG particle_reset_number;
static volatile LONG particle_activation_sequence_number;
static volatile LONG particle_activation_call_number;
static volatile LONG particle_activation_reset_number;
static volatile LONG presentation_sequence_number;
static volatile LONG render_list_call_number;
static volatile LONG airplane_presentation_call_number;
static volatile LONG shadow_render_sequence_number;
static volatile LONG shadow_render_call_number;
static volatile LONG shadow_camera_render_sequence_number;
static volatile LONG shadow_camera_render_call_number;
static volatile LONG shadow_render_room_sequence_number;
static volatile LONG shadow_render_room_call_number;
static volatile LONG shadow_visible_objects_sequence_number;
static volatile LONG shadow_visible_objects_call_number;
static volatile LONG shadow_visible_polygons_sequence_number;
static volatile LONG shadow_visible_polygons_call_number;
static volatile LONG shadow_polygon_render_sequence_number;
static volatile LONG shadow_polygon_render_call_number;
static volatile LONG shadow_world_relation_sequence_number;
static volatile LONG shadow_world_relation_call_number;
static volatile LONG shadow_rotation_setter_sequence_number;
static volatile LONG shadow_rotation_setter_call_number;
static MediaAudioInstance
    media_audio_instances[MEDIA_AUDIO_INSTANCE_CAPACITY];
static DWORD particle_active_tick_call = INVALID_ID;
static DWORD particle_active_reset = INVALID_ID;
static DWORD particle_active_activation_tick = INVALID_ID;
static DWORD particle_active_activation_reset = INVALID_ID;
static DWORD particle_active_activation_place = INVALID_ID;
static DWORD active_render_list_call = INVALID_ID;
static DWORD active_airplane_presentation_call = INVALID_ID;
static DWORD active_shadow_render_call = INVALID_ID;
static DWORD active_shadow_camera_call = INVALID_ID;
static DWORD active_shadow_render_room_call = INVALID_ID;
static DWORD active_shadow_visible_objects_call = INVALID_ID;
static DWORD active_shadow_visible_polygons_call = INVALID_ID;
static DWORD shadow_visible_polygons_render_heads[11u];
static DWORD shadow_visible_polygons_object;
static DWORD shadow_visible_polygons_camera;
static DWORD shadow_visible_polygons_render_list;
static DWORD shadow_visible_polygons_outline;
#define SHADOW_WORLD_RELATION_DEPTH 64u
static DWORD shadow_world_relation_depth;
static DWORD shadow_world_relation_calls[SHADOW_WORLD_RELATION_DEPTH];
static DWORD shadow_world_relation_nodes[SHADOW_WORLD_RELATION_DEPTH];
static DWORD shadow_world_relation_rooms[SHADOW_WORLD_RELATION_DEPTH];
static DWORD active_shadow_rotation_setter_call = INVALID_ID;
static DWORD active_shadow_rotation_setter_matrix;
static DWORD active_shadow_rotation_setter_caller;
static volatile LONG particle_activation_epoch_open;
static volatile LONG login_activation_observed;
static volatile LONG udsp_sequence_number;
static volatile LONG udsp_call_number;
static volatile LONG scene_dispatch_sequence_number;
static ObserverThread thread_contexts[THREAD_CONTEXT_COUNT];
static ModeTransitionObservation mode_transitions[MODE_TRANSITION_LIMIT];

static ReplayTick *replay_ticks;
static DWORD replay_tick_count;
static DWORD replay_next_tick;
static DWORD replay_active_tick = INVALID_ID;
static DWORD replay_active_dt;
static BYTE replay_active_keys;
static DWORD replay_complete_tick;
static DWORD replay_capture_tick;
static DWORD replay_flight_activation_seed;
static DWORD replay_rng_seed;
static DWORD replay_runtime_state[RUNTIME_STATE_FIELD_COUNT];
static BOOL replay_runtime_state_bound;
static DWORD *replay_activation_dts;
static DWORD replay_activation_dt_count;
static DWORD replay_activation_dt_next;
static BYTE replay_activation_clock_sha256[32];
static BOOL runtime_state_calibration;
static BOOL flight_activation_seed_applied;
static char replay_scenario[64];
static BYTE replay_sha256[32];
static BYTE replay_scenario_sha256[32];
static ReplayFocusEvent *replay_focus_events;
static DWORD replay_focus_event_count;
static BYTE replay_focus_timeline_sha256[32];
static volatile LONG replay_focus_next_event;
static volatile LONG replay_focus_scheduler_state;
static HANDLE replay_focus_arm_event;
static HANDLE replay_focus_applied_event;
static HANDLE replay_focus_stop_event;
static LARGE_INTEGER replay_focus_clock_frequency;
static LARGE_INTEGER replay_focus_episode_origin;
static DWORD replay_focus_armed_episode = INVALID_ID;
static DWORD replay_focus_applied_ordinal = INVALID_ID;
static ULONGLONG replay_focus_applied_offset_ns;
static BYTE initial_user_sha256[32];
static volatile LONG session_state = SESSION_WAIT_LOGIN;
static DWORD session_gate_count;
static BOOL barn_door_input_sent;
static BOOL barn_flight_input_sent;
static FlightBootstrapPhase flight_bootstrap_phase = BOOTSTRAP_WAIT_BARN;
static BOOL mygghanget_state_zero_observed;
static BOOL bootstrap_faster_input_down;
static BOOL bootstrap_faster_sample_observed;
static BOOL frame_captured;
static BOOL input_injected;
static BOOL os_input_initialized;
static BYTE os_input_keys;
static BYTE os_input_maybe_down;
static BYTE os_input_scripted_keys;
static BYTE os_input_target_focus = 1u;
static DWORD os_input_target_tick = INVALID_ID;
/* Bits released by the replay schedule whose SendInput KEYUP may not have
 * propagated to DirectInput's GetDeviceState.  On FEX-emu/ARM64, Wine's
 * input queue can silently lose KEYEVENTF_KEYUP events, so a key released
 * at the end of tick N may never appear released in the game's polled
 * keyboard state (mode+0x70).  force_release_lag_keys zeroes these bits
 * directly in the buffer before verify_replay_key_sample and the game's
 * own input logic read them, making replay deterministic regardless of
 * Wine input-queue behaviour.  The mask persists until send_replay_keys
 * clears it because the replay schedule re-pressed the key.
 * See force_release_lag_keys / send_replay_keys / verify_replay_key_sample. */
static BYTE os_input_release_lag;
static HWND projector_window;
static HWND focus_sink_window;
static volatile LONG engine_thread_id;
static BOOL native_dispatch_requested;
static BOOL native_dispatch_armed;
static BOOL native_dispatch_bound;
static BOOL detour_rollback_failed;
static DetourProtectionRecord
    detour_protection_records[DETOUR_PROTECTION_CAPACITY];
static const MvdsHookSpec *native_dispatch_specs;
static size_t native_dispatch_spec_count;
static size_t native_dispatch_installed_count;
static DWORD native_dispatch_installed_mask;
static MvdsHost native_dispatch_host;
static char native_dispatch_job_id[128];
static char native_dispatch_native_slice_sha256[65];
static char native_dispatch_observer_binary_sha256[65];
static char native_dispatch_build_receipt_sha256[65];
static char native_dispatch_target_sha256[65];
static char native_dispatch_job_sha256[65];
static char native_dispatch_claim_id[128];
static char native_dispatch_claim_sha256[65];
static char native_dispatch_subject_sha256[65];
static char native_dispatch_expectation_sha256[65];
static char native_dispatch_scenario_sha256[65];
static char native_dispatch_capture_plan_sha256[65];
static char native_dispatch_plan_manifest_sha256[65];
static MvdsCaptureTarget native_dispatch_capture_target;
static volatile LONG manager_tick_count;
static volatile LONG manager_render_count;
static volatile LONG manager_render_active;
static volatile LONG camera_commit_count;
static DWORD camera_checkpoint_tick = INVALID_ID;
static DWORD render_checkpoint_tick = INVALID_ID;

static DWORD record_tick(DWORD manager_node, DWORD dt_f32_bits);
static BOOL read_pointer(DWORD object_address, DWORD offset, DWORD *value);
static void fail_activation_rng(void);
static void fail_activation_clock(const char *reason);
static void fail_location_phase_rng(void);
static void record_camera_commit(DWORD controller_address);
static BOOL install_manager_render_interposition(void);
static BOOL install_shadow_render_interposition(void);
static BOOL complete_observer_bootstrap(DWORD expected_manager);
static BOOL ensure_calibration_manager_tick_interposition(void);
static BOOL native_capture_driver_complete(void);
static BOOL native_capture_driver_needs_flight_bootstrap(void);
static void dispatch_native_capture_driver_on_manager_tick(
    DWORD manager_address);
static void record_render_final(DWORD controller_address,
                                DWORD device_address);
static HANDLE complete_event;
static HANDLE failure_event;
static HANDLE ready_event;
static HANDLE login_pending_event;
static HANDLE login_activation_event;
static HANDLE native_dispatch_complete_event;
static HANDLE late_bootstrap_event;
static HANDLE native_dispatch_identity_mapping;
static MvdsSharedProcessIdentity *native_dispatch_shared_identity;
static volatile LONG observer_ready;
static char frame_prefix[MAX_PATH * 2];

typedef int (__cdecl *RandFunction)(void);
typedef void (__cdecl *SrandFunction)(unsigned int);
typedef void *(__attribute__((thiscall)) *AudioStartFunction)(void *, DWORD);
typedef BYTE (__attribute__((thiscall)) *AudioPollFunction)(void *);
static RandFunction original_rand;
static SrandFunction original_srand;
static DWORD rng_draw_count;
static DWORD rng_seed_count;
static Sha256Context flight_activation_rng_sha256;
static DWORD flight_activation_rng_count;
static BOOL flight_activation_rng_open;
static Sha256Context location_phase_rng_sha256;
static DWORD location_phase_rng_count;
static BOOL location_phase_rng_seeded;
static BOOL location_phase_rng_complete;
static Sha256Context flight_activation_clock_sha256;
static DWORD flight_activation_clock_count;
static BOOL flight_activation_clock_open;

typedef void *(__attribute__((thiscall)) *ReadScreenFunction)(void *, void *);
typedef DWORD *(__attribute__((thiscall)) *PositionResolveFunction)(
    void *, DWORD *);
typedef int (__attribute__((thiscall)) *ImageLevelIntFunction)(void *, int);
typedef void *(__attribute__((thiscall)) *ImagePointerFunction)(void *, int);
typedef int (__attribute__((thiscall)) *ImageIntFunction)(void *);
typedef void (__attribute__((thiscall)) *ImageDestructorFunction)(void *);
static ReadScreenFunction read_screen_export;
static ImageLevelIntFunction image_get_width;
static ImageLevelIntFunction image_get_height;
static ImageLevelIntFunction image_get_pitch;
static ImageLevelIntFunction image_get_size;
static ImagePointerFunction image_get_pointer;
static ImageIntFunction image_get_pixel_size;
static ImageIntFunction image_get_format;
static ImageDestructorFunction image_destructor;
static const char *framebuffer_export_error;
static const char *framebuffer_capture_error;

static void session_fail(const char *reason);

static BOOL trampoline_contains_fault(
    void *trampoline, DWORD instruction, DWORD *offset_out)
{
    MEMORY_BASIC_INFORMATION trampoline_info, instruction_info;
    if (!trampoline ||
        VirtualQuery(trampoline, &trampoline_info,
                     sizeof(trampoline_info)) != sizeof(trampoline_info) ||
        VirtualQuery((const void *)(ULONG_PTR)instruction, &instruction_info,
                     sizeof(instruction_info)) != sizeof(instruction_info) ||
        trampoline_info.AllocationBase != instruction_info.AllocationBase) {
        return FALSE;
    }
    *offset_out = instruction - (DWORD)(ULONG_PTR)trampoline;
    return TRUE;
}

static LONG WINAPI record_bootstrap_exception(EXCEPTION_POINTERS *exception)
{
    const char *owner = "unclassified";
    const char *code_name;
    DWORD offset = 0u, allocation_offset = 0u, written = 0u;
    DWORD exception_code;
    size_t native_dispatch_index;
    BYTE instruction_bytes[16] = {0};
    SIZE_T instruction_byte_count = 0u;
    DWORD stack_words[8] = {0};
    SIZE_T stack_byte_count = 0u;
    MEMORY_BASIC_INFORMATION instruction_info;
    char access_kind_json[16];
    char line[1024];
    int size;
#define CLASSIFY_TRAMPOLINE(pointer, label) \
    if (strcmp(owner, "unclassified") == 0 && \
        trampoline_contains_fault(pointer, exception->ContextRecord->Eip, \
                                  &offset)) owner = label
    if (!bootstrap_diagnostics_enabled || !exception ||
        !exception->ExceptionRecord || !exception->ContextRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    exception_code = exception->ExceptionRecord->ExceptionCode;
    if (exception_code == EXCEPTION_ACCESS_VIOLATION) {
        code_name = "ACCESS_VIOLATION";
        snprintf(access_kind_json, sizeof(access_kind_json), "%lu",
            (unsigned long)exception->ExceptionRecord->ExceptionInformation[0]);
    } else if (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) {
        code_name = "ILLEGAL_INSTRUCTION";
        strcpy(access_kind_json, "null");
    } else {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    CLASSIFY_TRAMPOLINE(mode_set_trampoline, "mode_set");
    CLASSIFY_TRAMPOLINE(queue_mode_trampoline, "queue_mode");
    CLASSIFY_TRAMPOLINE(flight_target_trampoline, "flight_target");
    CLASSIFY_TRAMPOLINE(exhibition_callback_trampoline,
                        "exhibition_callback");
    CLASSIFY_TRAMPOLINE(udsp_dispatch_trampoline, "udsp_dispatch");
    CLASSIFY_TRAMPOLINE(udsp_root_update_trampoline, "udsp_root_update");
    CLASSIFY_TRAMPOLINE(udsp_root_start_trampoline, "udsp_root_start");
    CLASSIFY_TRAMPOLINE(scene_dispatch_barn_trampoline,
                        "scene_dispatch_barn");
    CLASSIFY_TRAMPOLINE(scene_dispatch_ground_trampoline,
                        "scene_dispatch_ground");
    CLASSIFY_TRAMPOLINE(scene_dispatch_flight_trampoline,
                        "scene_dispatch_flight");
    CLASSIFY_TRAMPOLINE(controls_pre_trampoline, "controls_pre");
    CLASSIFY_TRAMPOLINE(controls_post_trampoline, "controls_post");
    CLASSIFY_TRAMPOLINE(flight_entry_trampoline, "flight_entry");
    CLASSIFY_TRAMPOLINE(flight_leave_trampoline, "flight_leave");
    CLASSIFY_TRAMPOLINE(collision_entry_trampoline, "collision_entry");
    CLASSIFY_TRAMPOLINE(collision_commit_trampoline, "collision_commit");
    CLASSIFY_TRAMPOLINE(camera_commit_trampoline, "camera_commit");
    CLASSIFY_TRAMPOLINE(render_final_trampoline, "render_final");
    CLASSIFY_TRAMPOLINE(fuel_depletion_trampoline, "fuel_depletion");
    CLASSIFY_TRAMPOLINE(fuel_post_consume_trampoline, "fuel_post_consume");
    CLASSIFY_TRAMPOLINE(contact_trampoline, "contact");
    CLASSIFY_TRAMPOLINE(damage_effective_trampoline, "damage_effective");
    CLASSIFY_TRAMPOLINE(damage_post_trampoline, "damage_post");
    CLASSIFY_TRAMPOLINE(damage_nonterminal_trampoline, "damage_nonterminal");
    CLASSIFY_TRAMPOLINE(terminal_crash_trampoline, "terminal_crash");
    CLASSIFY_TRAMPOLINE(terrain_result_crash_trampoline, "terrain_crash");
    CLASSIFY_TRAMPOLINE(terrain_result_render_trampoline, "terrain_render");
    CLASSIFY_TRAMPOLINE(particle_emitter_tick_trampoline, "particle_tick");
    CLASSIFY_TRAMPOLINE(particle_reset_trampoline, "particle_reset");
    CLASSIFY_TRAMPOLINE(particle_place_trampoline, "particle_place");
    CLASSIFY_TRAMPOLINE(render_list_dispatch_trampoline,
                        "render_list_dispatch");
    CLASSIFY_TRAMPOLINE(airplane_presentation_trampoline,
                        "airplane_presentation");
    for (native_dispatch_index = 0u;
         strcmp(owner, "unclassified") == 0 && native_dispatch_specs &&
             native_dispatch_index < native_dispatch_spec_count;
         ++native_dispatch_index) {
        const MvdsHookSpec *spec =
            &native_dispatch_specs[native_dispatch_index];
        CLASSIFY_TRAMPOLINE(*spec->trampoline_slot, spec->name);
    }
#undef CLASSIFY_TRAMPOLINE
    memset(&instruction_info, 0, sizeof(instruction_info));
    if (VirtualQuery(
            (const void *)(ULONG_PTR)exception->ContextRecord->Eip,
            &instruction_info, sizeof(instruction_info)) ==
            sizeof(instruction_info)) {
        allocation_offset = exception->ContextRecord->Eip -
            (DWORD)(ULONG_PTR)instruction_info.AllocationBase;
        ReadProcessMemory(
            GetCurrentProcess(),
            (const void *)(ULONG_PTR)exception->ContextRecord->Eip,
            instruction_bytes, sizeof(instruction_bytes),
            &instruction_byte_count);
    }
    ReadProcessMemory(
        GetCurrentProcess(),
        (const void *)(ULONG_PTR)exception->ContextRecord->Esp,
        stack_words, sizeof(stack_words), &stack_byte_count);
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,\"protocol\":\"miel-vliegt-native-exception\","
        "\"code\":\"%s\",\"trampoline\":\"%s\","
        "\"trampoline_offset\":%lu,\"access_kind\":%s,"
        "\"allocation_offset\":%lu,\"region_type\":%lu,"
        "\"region_protect\":%lu,\"instruction_bytes\":"
        "\"%02x%02x%02x%02x%02x%02x%02x%02x"
        "%02x%02x%02x%02x%02x%02x%02x%02x\","
        "\"instruction_byte_count\":%lu,"
        "\"registers\":{\"eax\":\"0x%08lx\",\"ebx\":\"0x%08lx\","
        "\"ecx\":\"0x%08lx\",\"edx\":\"0x%08lx\","
        "\"esi\":\"0x%08lx\",\"edi\":\"0x%08lx\","
        "\"ebp\":\"0x%08lx\",\"esp\":\"0x%08lx\"},"
        "\"stack_words\":[\"0x%08lx\",\"0x%08lx\",\"0x%08lx\","
        "\"0x%08lx\",\"0x%08lx\",\"0x%08lx\",\"0x%08lx\","
        "\"0x%08lx\"],\"stack_byte_count\":%lu,\"thread_id\":%lu}\r\n",
        code_name, owner, (unsigned long)offset, access_kind_json,
        (unsigned long)allocation_offset,
        (unsigned long)instruction_info.Type,
        (unsigned long)instruction_info.Protect,
        instruction_bytes[0], instruction_bytes[1],
        instruction_bytes[2], instruction_bytes[3],
        instruction_bytes[4], instruction_bytes[5],
        instruction_bytes[6], instruction_bytes[7],
        instruction_bytes[8], instruction_bytes[9],
        instruction_bytes[10], instruction_bytes[11],
        instruction_bytes[12], instruction_bytes[13],
        instruction_bytes[14], instruction_bytes[15],
        (unsigned long)instruction_byte_count,
        (unsigned long)exception->ContextRecord->Eax,
        (unsigned long)exception->ContextRecord->Ebx,
        (unsigned long)exception->ContextRecord->Ecx,
        (unsigned long)exception->ContextRecord->Edx,
        (unsigned long)exception->ContextRecord->Esi,
        (unsigned long)exception->ContextRecord->Edi,
        (unsigned long)exception->ContextRecord->Ebp,
        (unsigned long)exception->ContextRecord->Esp,
        (unsigned long)stack_words[0], (unsigned long)stack_words[1],
        (unsigned long)stack_words[2], (unsigned long)stack_words[3],
        (unsigned long)stack_words[4], (unsigned long)stack_words[5],
        (unsigned long)stack_words[6], (unsigned long)stack_words[7],
        (unsigned long)stack_byte_count,
        (unsigned long)GetCurrentThreadId());
    if (trace_file != INVALID_HANDLE_VALUE && size > 0 &&
        (size_t)size < sizeof(line)) {
        WriteFile(trace_file, line, (DWORD)size, &written, NULL);
        FlushFileBuffers(trace_file);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD rotate_right(DWORD value, DWORD count)
{
    return (value >> count) | (value << (32u - count));
}

static DWORD load_be32(const BYTE *bytes)
{
    return ((DWORD)bytes[0] << 24) | ((DWORD)bytes[1] << 16) |
           ((DWORD)bytes[2] << 8) | (DWORD)bytes[3];
}

static void store_be32(BYTE *bytes, DWORD value)
{
    bytes[0] = (BYTE)(value >> 24);
    bytes[1] = (BYTE)(value >> 16);
    bytes[2] = (BYTE)(value >> 8);
    bytes[3] = (BYTE)value;
}

static void sha256_transform(Sha256Context *context, const BYTE block[64])
{
    static const DWORD constants[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };
    DWORD words[64];
    DWORD a, b, c, d, e, f, g, h, index;
    for (index = 0u; index < 16u; ++index) {
        words[index] = load_be32(block + index * 4u);
    }
    for (index = 16u; index < 64u; ++index) {
        DWORD s0 = rotate_right(words[index - 15u], 7u) ^
                   rotate_right(words[index - 15u], 18u) ^
                   (words[index - 15u] >> 3);
        DWORD s1 = rotate_right(words[index - 2u], 17u) ^
                   rotate_right(words[index - 2u], 19u) ^
                   (words[index - 2u] >> 10);
        words[index] = words[index - 16u] + s0 + words[index - 7u] + s1;
    }
    a = context->state[0]; b = context->state[1];
    c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5];
    g = context->state[6]; h = context->state[7];
    for (index = 0u; index < 64u; ++index) {
        DWORD sum1 = rotate_right(e, 6u) ^ rotate_right(e, 11u) ^
                     rotate_right(e, 25u);
        DWORD choice = (e & f) ^ ((~e) & g);
        DWORD temp1 = h + sum1 + choice + constants[index] + words[index];
        DWORD sum0 = rotate_right(a, 2u) ^ rotate_right(a, 13u) ^
                     rotate_right(a, 22u);
        DWORD majority = (a & b) ^ (a & c) ^ (b & c);
        DWORD temp2 = sum0 + majority;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    context->state[0] += a; context->state[1] += b;
    context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f;
    context->state[6] += g; context->state[7] += h;
}

static void sha256_init(Sha256Context *context)
{
    static const DWORD initial[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    memcpy(context->state, initial, sizeof(initial));
    context->bit_count = 0u;
    context->block_used = 0u;
}

static void sha256_update(Sha256Context *context, const BYTE *bytes, DWORD size)
{
    context->bit_count += (ULONGLONG)size * 8u;
    while (size != 0u) {
        DWORD available = 64u - context->block_used;
        DWORD take = size < available ? size : available;
        memcpy(context->block + context->block_used, bytes, take);
        context->block_used += take;
        bytes += take;
        size -= take;
        if (context->block_used == 64u) {
            sha256_transform(context, context->block);
            context->block_used = 0u;
        }
    }
}

static void sha256_final(Sha256Context *context, BYTE digest[32])
{
    BYTE padding[72] = {0x80};
    BYTE length_bytes[8];
    ULONGLONG bits = context->bit_count;
    DWORD pad_size = context->block_used < 56u ?
        56u - context->block_used : 120u - context->block_used;
    DWORD index;
    for (index = 0u; index < 8u; ++index) {
        length_bytes[7u - index] = (BYTE)(bits >> (index * 8u));
    }
    sha256_update(context, padding, pad_size);
    sha256_update(context, length_bytes, sizeof(length_bytes));
    for (index = 0u; index < 8u; ++index) {
        store_be32(digest + index * 4u, context->state[index]);
    }
}

static BOOL decode_sha256(const char *text, BYTE digest[32])
{
    DWORD index;
    for (index = 0u; index < 64u; ++index) {
        BYTE value;
        char character = text[index];
        if (character >= '0' && character <= '9') value = (BYTE)(character - '0');
        else if (character >= 'a' && character <= 'f') value = (BYTE)(character - 'a' + 10);
        else return FALSE;
        if ((index & 1u) == 0u) digest[index / 2u] = (BYTE)(value << 4);
        else digest[index / 2u] |= value;
    }
    return text[64] == '\0';
}

static void encode_sha256(const BYTE digest[32], char text[65])
{
    static const char digits[] = "0123456789abcdef";
    DWORD index;
    for (index = 0u; index < 32u; ++index) {
        text[index * 2u] = digits[digest[index] >> 4];
        text[index * 2u + 1u] = digits[digest[index] & 15u];
    }
    text[64] = '\0';
}

static BOOL hash_file(const char *path, BYTE digest[32])
{
    BYTE buffer[16384];
    DWORD read_size;
    Sha256Context context;
    HANDLE file = CreateFileA(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    sha256_init(&context);
    do {
        if (!ReadFile(file, buffer, sizeof(buffer), &read_size, NULL)) {
            CloseHandle(file);
            return FALSE;
        }
        sha256_update(&context, buffer, read_size);
    } while (read_size != 0u);
    CloseHandle(file);
    sha256_final(&context, digest);
    return TRUE;
}

static BOOL establish_natural_observer_identity(void)
{
    HMODULE module = NULL;
    char path[MAX_PATH * 2];
    BYTE digest[32];
    DWORD length;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)(ULONG_PTR)&MielObserverInitialize, &module)) {
        return FALSE;
    }
    length = GetModuleFileNameA(module, path, sizeof(path));
    if (length == 0u || length >= sizeof(path) || !hash_file(path, digest)) {
        return FALSE;
    }
    encode_sha256(digest, natural_observer_sha256);
    return TRUE;
}

static BOOL write_all(const char *text, DWORD size)
{
    while (size != 0u) {
        DWORD written = 0;
        if (trace_file == INVALID_HANDLE_VALUE ||
            !WriteFile(trace_file, text, size, &written, NULL) || written == 0u) {
            return FALSE;
        }
        text += written;
        size -= written;
    }
    return TRUE;
}

static void flush_trace_locked(void)
{
    if (trace_buffer_used == 0u || trace_write_failed) return;
    if (!write_all(trace_buffer, trace_buffer_used)) trace_write_failed = TRUE;
    trace_buffer_used = 0u;
}

static void append_raw_locked(const char *text, DWORD size)
{
    if (size == 0u || size > TRACE_BUFFER_SIZE || trace_write_failed) return;
    if (trace_buffer_used + size > TRACE_BUFFER_SIZE) flush_trace_locked();
    if (trace_write_failed) return;
    memcpy(trace_buffer + trace_buffer_used, text, size);
    trace_buffer_used += size;
}

static void append_record_locked(const char *text, DWORD size)
{
    static const char limit_marker[] =
        "MVO {\"schema\":1,\"protocol\":\"miel-vliegt-native-observer-hook\","
        "\"status\":\"TRACE_LIMIT\"}\r\n";
    if (trace_record_count >= trace_record_limit) {
        if (!trace_saturated) {
            trace_saturated = TRUE;
            append_raw_locked(limit_marker, (DWORD)(sizeof(limit_marker) - 1u));
        }
    } else {
        ++trace_record_count;
        append_raw_locked(text, size);
    }
}

static void append_record(const char *text, DWORD size)
{
    if (!trace_lock_ready) return;
    EnterCriticalSection(&trace_lock);
    append_record_locked(text, size);
    LeaveCriticalSection(&trace_lock);
}

static BOOL append_record_checked(const char *text, DWORD size)
{
    BOOL accepted = FALSE;
    DWORD before_count;
    if (!trace_lock_ready || size == 0u || size > TRACE_BUFFER_SIZE) {
        return FALSE;
    }
    EnterCriticalSection(&trace_lock);
    before_count = trace_record_count;
    if (!trace_saturated && !trace_write_failed &&
        before_count < trace_record_limit) {
        append_record_locked(text, size);
        accepted = !trace_saturated && !trace_write_failed &&
            trace_record_count == before_count + 1u;
    }
    LeaveCriticalSection(&trace_lock);
    return accepted;
}

static BOOL append_record_durable_checked(const char *text, DWORD size)
{
    BOOL accepted = FALSE;
    DWORD before_count;
    if (!trace_lock_ready || size == 0u || size > TRACE_BUFFER_SIZE) {
        return FALSE;
    }
    EnterCriticalSection(&trace_lock);
    before_count = trace_record_count;
    if (!trace_saturated && !trace_write_failed &&
        before_count < trace_record_limit) {
        append_record_locked(text, size);
        flush_trace_locked();
        if (!trace_write_failed && trace_file != INVALID_HANDLE_VALUE &&
            FlushFileBuffers(trace_file)) {
            accepted = !trace_saturated &&
                trace_record_count == before_count + 1u;
        } else {
            trace_write_failed = TRUE;
        }
    }
    LeaveCriticalSection(&trace_lock);
    return accepted;
}

static void flush_trace(void)
{
    if (!trace_lock_ready) return;
    EnterCriticalSection(&trace_lock);
    flush_trace_locked();
    LeaveCriticalSection(&trace_lock);
}

static DWORD next_id(volatile LONG *counter)
{
    return (DWORD)InterlockedIncrement(counter) - 1u;
}

static DWORD current_frame(void)
{
    return (DWORD)InterlockedCompareExchange(&frame_number, 0, 0);
}

static void write_marker(const char *status)
{
    char line[256];
    int size = snprintf(
        line, sizeof(line),
        "MVO {\"schema\":1,\"protocol\":\"miel-vliegt-native-observer-hook\","
        "\"status\":\"%s\",\"thread_id\":%lu}\r\n",
        status, (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) {
        append_record(line, (DWORD)size);
    }
}

static BOOL get_required_environment(const char *name, char *output,
                                     DWORD capacity)
{
    DWORD length = GetEnvironmentVariableA(name, output, capacity);
    return length != 0u && length < capacity;
}

static BOOL parse_decimal(const char *text, DWORD *value)
{
    DWORD result = 0u;
    if (*text == '\0') return FALSE;
    while (*text != '\0') {
        DWORD digit;
        if (*text < '0' || *text > '9') return FALSE;
        digit = (DWORD)(*text - '0');
        if (result > (0xffffffffu - digit) / 10u) return FALSE;
        result = result * 10u + digit;
        ++text;
    }
    *value = result;
    return TRUE;
}

static BOOL parse_decimal_u64(const char *text, ULONGLONG *value)
{
    ULONGLONG result = 0u;
    if (*text == '\0') return FALSE;
    while (*text != '\0') {
        ULONGLONG digit;
        if (*text < '0' || *text > '9') return FALSE;
        digit = (ULONGLONG)(*text - '0');
        if (result > (0xffffffffffffffffull - digit) / 10ull) return FALSE;
        result = result * 10ull + digit;
        ++text;
    }
    *value = result;
    return TRUE;
}

static BOOL parse_fixed_hex(const char *text, DWORD digits, DWORD *value)
{
    DWORD result = 0u;
    DWORD index;
    for (index = 0u; index < digits; ++index) {
        DWORD digit;
        char character = text[index];
        if (character >= '0' && character <= '9') digit = (DWORD)(character - '0');
        else if (character >= 'a' && character <= 'f') digit = (DWORD)(character - 'a' + 10);
        else return FALSE;
        result = (result << 4) | digit;
    }
    if (text[digits] != '\0') return FALSE;
    *value = result;
    return TRUE;
}

static char *take_line(char **cursor)
{
    char *line;
    char *end;
    if (!cursor || !*cursor || **cursor == '\0') return NULL;
    line = *cursor;
    end = line;
    while (*end != '\0' && *end != '\r' && *end != '\n') ++end;
    if (*end == '\r') {
        *end++ = '\0';
        if (*end != '\n') return NULL;
        *end++ = '\0';
    } else if (*end == '\n') {
        *end++ = '\0';
    }
    *cursor = end;
    return line;
}

static BOOL valid_scenario_id(const char *text)
{
    DWORD length = 0u;
    while (text[length] != '\0') {
        char c = text[length];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) {
            return FALSE;
        }
        if (++length >= sizeof(replay_scenario)) return FALSE;
    }
    return length != 0u;
}

static BOOL parse_replay_focus_event(char *line, DWORD ordinal,
                                     ReplayFocusEvent *event)
{
    char prefix[48];
    char *tick_text;
    char *active_text;
    char *episode_text;
    char *offset_text;
    DWORD active;
    int prefix_size = snprintf(
        prefix, sizeof(prefix), "focus_event.%lu=", (unsigned long)ordinal);
    if (prefix_size <= 0 || (size_t)prefix_size >= sizeof(prefix) ||
        strncmp(line, prefix, (size_t)prefix_size) != 0) return FALSE;
    tick_text = line + prefix_size;
    active_text = strchr(tick_text, ' ');
    if (!active_text) return FALSE;
    *active_text++ = '\0';
    episode_text = strchr(active_text, ' ');
    if (!episode_text) return FALSE;
    *episode_text++ = '\0';
    offset_text = strchr(episode_text, ' ');
    if (!offset_text || strchr(offset_text + 1, ' ')) return FALSE;
    *offset_text++ = '\0';
    event->ordinal = ordinal;
    return parse_decimal(tick_text, &event->tick) &&
        parse_decimal(active_text, &active) && active <= 1u &&
        parse_decimal(episode_text, &event->episode) &&
        parse_decimal_u64(offset_text, &event->offset_ns) &&
        ((event->active = (BYTE)active), TRUE);
}

static BOOL validate_replay_focus_timeline(void)
{
    Sha256Context hash;
    BYTE digest[32];
    DWORD event_index = 0u;
    DWORD tick;
    BYTE previous_focus = 1u;
    DWORD expected_episode = 0u;
    BOOL episode_open = FALSE;
    sha256_init(&hash);
    for (tick = 0u; tick < replay_tick_count; ++tick) {
        ReplayTick *replay_tick = &replay_ticks[tick];
        ReplayFocusEvent *event;
        if (replay_tick->focus_active == previous_focus) continue;
        if (event_index >= replay_focus_event_count) return FALSE;
        event = &replay_focus_events[event_index];
        if (event->ordinal != event_index || event->tick != tick ||
            event->active != replay_tick->focus_active) return FALSE;
        if (!event->active) {
            if (tick == 0u || episode_open ||
                event->episode != expected_episode ||
                event->offset_ns != 0u) return FALSE;
            episode_open = TRUE;
        } else {
            if (!episode_open || event->episode != expected_episode ||
                event->offset_ns == 0u) return FALSE;
            episode_open = FALSE;
            ++expected_episode;
        }
        sha256_update(&hash, (const BYTE *)&event->ordinal,
                      sizeof(event->ordinal));
        sha256_update(&hash, (const BYTE *)&event->episode,
                      sizeof(event->episode));
        sha256_update(&hash, (const BYTE *)&event->tick,
                      sizeof(event->tick));
        sha256_update(&hash, &event->active, sizeof(event->active));
        sha256_update(&hash, (const BYTE *)&event->offset_ns,
                      sizeof(event->offset_ns));
        previous_focus = replay_tick->focus_active;
        ++event_index;
    }
    if (episode_open || event_index != replay_focus_event_count) return FALSE;
    sha256_final(&hash, digest);
    return memcmp(digest, replay_focus_timeline_sha256, sizeof(digest)) == 0;
}

static BOOL parse_replay_file(const char *path, const BYTE expected_hash[32])
{
    LARGE_INTEGER size;
    DWORD read_size;
    BYTE actual_hash[32];
    char *bytes;
    char *cursor;
    char *line;
    HANDLE file;
    DWORD index;
    BOOL wire_v2;
    BOOL wire_v3;
    BOOL focus_timeline_bound = FALSE;
    if (!hash_file(path, actual_hash) ||
        memcmp(actual_hash, expected_hash, sizeof(actual_hash)) != 0) return FALSE;
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE || !GetFileSizeEx(file, &size) ||
        size.QuadPart <= 0 || size.QuadPart > MAX_SCENARIO_SIZE) {
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        return FALSE;
    }
    bytes = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size.QuadPart + 1u);
    if (!bytes || !ReadFile(file, bytes, (DWORD)size.QuadPart, &read_size, NULL) ||
        read_size != (DWORD)size.QuadPart) {
        if (bytes) HeapFree(GetProcessHeap(), 0, bytes);
        CloseHandle(file);
        return FALSE;
    }
    CloseHandle(file);
    bytes[read_size] = '\0';
    if (memchr(bytes, '\0', read_size) != NULL) goto parse_failed;
    cursor = bytes;
    line = take_line(&cursor);
    if (!line) goto parse_failed;
    if (strcmp(line, "MVO_REPLAY_V3") == 0) {
        wire_v2 = TRUE;
        wire_v3 = TRUE;
    } else if (strcmp(line, "MVO_REPLAY_V2") == 0) {
        wire_v2 = TRUE;
        wire_v3 = FALSE;
    } else if (strcmp(line, "MVO_REPLAY_V1") == 0) {
        wire_v2 = FALSE;
        wire_v3 = FALSE;
    }
    else goto parse_failed;
    line = take_line(&cursor);
    if (!line || strncmp(line, "scenario=", 9u) != 0 ||
        !valid_scenario_id(line + 9u)) goto parse_failed;
    strcpy(replay_scenario, line + 9u);
    line = take_line(&cursor);
    if (line && strncmp(line, "scenario_sha256=", 16u) == 0) {
        focus_timeline_bound = TRUE;
        if (!decode_sha256(line + 16u, replay_scenario_sha256)) {
            goto parse_failed;
        }
        line = take_line(&cursor);
        if (!line || strncmp(line, "focus_event_count=", 18u) != 0 ||
            !parse_decimal(line + 18u, &replay_focus_event_count) ||
            replay_focus_event_count > MAX_REPLAY_FOCUS_EVENTS) {
            goto parse_failed;
        }
        if (replay_focus_event_count != 0u) {
            replay_focus_events = (ReplayFocusEvent *)HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY,
                (SIZE_T)replay_focus_event_count *
                    sizeof(*replay_focus_events));
            if (!replay_focus_events) goto parse_failed;
        }
        for (index = 0u; index < replay_focus_event_count; ++index) {
            line = take_line(&cursor);
            if (!line || !parse_replay_focus_event(
                    line, index, &replay_focus_events[index])) {
                goto parse_failed;
            }
        }
        line = take_line(&cursor);
        if (!line || strncmp(line, "focus_timeline_sha256=", 22u) != 0 ||
            !decode_sha256(
                line + 22u, replay_focus_timeline_sha256)) {
            goto parse_failed;
        }
        line = take_line(&cursor);
    }
    if (wire_v3) {
        if (!line || strncmp(line, "flight_activation_seed=", 23u) != 0 ||
            !parse_decimal(line + 23u, &replay_flight_activation_seed)) {
            goto parse_failed;
        }
        line = NULL;
    }
    if (!line) line = take_line(&cursor);
    if (!line || strncmp(line, "rng_seed=", 9u) != 0 ||
        !parse_decimal(line + 9u, &replay_rng_seed)) goto parse_failed;
    if (!wire_v3) replay_flight_activation_seed = replay_rng_seed;
    line = take_line(&cursor);
    if (!line || strncmp(line, "capture_tick=", 13u) != 0 ||
        !parse_decimal(line + 13u, &replay_capture_tick)) goto parse_failed;
    line = take_line(&cursor);
    if (!line || strncmp(line, "complete_tick=", 14u) != 0 ||
        !parse_decimal(line + 14u, &replay_complete_tick) ||
        replay_complete_tick >= MAX_REPLAY_TICKS ||
        replay_capture_tick > replay_complete_tick) goto parse_failed;
    if (wire_v3) {
        line = take_line(&cursor);
        if (!line || strcmp(line, "state_count=39") != 0) goto parse_failed;
        for (index = 0u; index < RUNTIME_STATE_FIELD_COUNT; ++index) {
            char prefix[96];
            size_t prefix_length;
            DWORD value;
            const RuntimeStateField *field = &RUNTIME_STATE_FIELDS[index];
            int prefix_size = snprintf(prefix, sizeof(prefix), "state.%s=", field->name);
            if (prefix_size <= 0 || (size_t)prefix_size >= sizeof(prefix)) {
                goto parse_failed;
            }
            prefix_length = (size_t)prefix_size;
            line = take_line(&cursor);
            if (!line || strncmp(line, prefix, prefix_length) != 0 ||
                !parse_fixed_hex(line + prefix_length,
                                 field->width == 1u ? 2u : 8u, &value)) {
                goto parse_failed;
            }
            replay_runtime_state[index] = value;
        }
        replay_runtime_state_bound = TRUE;
        line = take_line(&cursor);
        if (!line || strncmp(line, "activation_tick_count=", 22u) != 0 ||
            !parse_decimal(line + 22u, &replay_activation_dt_count) ||
            replay_activation_dt_count > MAX_REPLAY_TICKS) {
            goto parse_failed;
        }
        if (replay_activation_dt_count != 0u) {
            replay_activation_dts = (DWORD *)HeapAlloc(
                GetProcessHeap(), 0,
                (SIZE_T)replay_activation_dt_count * sizeof(*replay_activation_dts));
            if (!replay_activation_dts) goto parse_failed;
        }
        for (index = 0u; index < replay_activation_dt_count; ++index) {
            char prefix[64];
            size_t prefix_length;
            DWORD value;
            int prefix_size = snprintf(
                prefix, sizeof(prefix), "activation_dt.%lu=", (unsigned long)index);
            if (prefix_size <= 0 || (size_t)prefix_size >= sizeof(prefix)) {
                goto parse_failed;
            }
            prefix_length = (size_t)prefix_size;
            line = take_line(&cursor);
            if (!line || strncmp(line, prefix, prefix_length) != 0 ||
                !parse_fixed_hex(line + prefix_length, 8u, &value) ||
                (value & 0x80000000u) != 0u ||
                (value & 0x7f800000u) == 0x7f800000u ||
                (value & 0x7fffffffu) == 0u) {
                goto parse_failed;
            }
            replay_activation_dts[index] = value;
        }
        line = take_line(&cursor);
        if (!line || strncmp(line, "activation_clock_sha256=", 24u) != 0 ||
            !decode_sha256(line + 24u, replay_activation_clock_sha256)) {
            goto parse_failed;
        }
    } else {
        replay_runtime_state_bound = FALSE;
        replay_activation_dt_count = 0u;
    }
    replay_tick_count = replay_complete_tick + 1u;
    /* Use VirtualAlloc instead of HeapAlloc for the replay tick array.
     * Under FEX-2607, the process heap can collide with the JIT code cache
     * for larger replay files (takeoff-climb: 2145 ticks ~= 43 KB vs
     * controls: 228 ticks ~= 5 KB). VirtualAlloc places the allocation
     * in a page-aligned region that avoids the JIT cache collision. */
    replay_ticks = (ReplayTick *)VirtualAlloc(
        NULL, (SIZE_T)replay_tick_count * sizeof(*replay_ticks),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!replay_ticks) goto parse_failed;
    for (index = 0u; index < replay_tick_count; ++index) {
        char *first_space;
        char *second_space;
        char *third_space = NULL;
        DWORD tick_value;
        DWORD dt_value;
        DWORD keys_value;
        DWORD focus_value = 1u;
        line = take_line(&cursor);
        if (!line) goto parse_failed;
        first_space = strchr(line, ' ');
        if (!first_space) goto parse_failed;
        *first_space++ = '\0';
        second_space = strchr(first_space, ' ');
        if (!second_space) goto parse_failed;
        *second_space++ = '\0';
        if (wire_v2) {
            third_space = strchr(second_space, ' ');
            if (!third_space || strchr(third_space + 1, ' ')) goto parse_failed;
            *third_space++ = '\0';
            if (!parse_decimal(third_space, &focus_value) || focus_value > 1u) {
                goto parse_failed;
            }
        } else if (strchr(second_space, ' ')) goto parse_failed;
        if (!parse_decimal(line, &tick_value) || tick_value != index ||
            !parse_fixed_hex(first_space, 8u, &dt_value) ||
            !parse_fixed_hex(second_space, 2u, &keys_value) ||
            (dt_value & 0x80000000u) != 0u ||
            (dt_value & 0x7f800000u) == 0x7f800000u ||
            (dt_value & 0x7fffffffu) == 0u ||
            (keys_value & ~REPLAY_KEY_MASK) != 0u) goto parse_failed;
        replay_ticks[index].tick = index;
        replay_ticks[index].dt_f32_bits = dt_value;
        replay_ticks[index].keys = (BYTE)keys_value;
        replay_ticks[index].focus_active = (BYTE)focus_value;
    }
    if (replay_ticks[replay_tick_count - 1u].keys != 0u ||
        replay_ticks[replay_tick_count - 1u].focus_active != 1u) {
        goto parse_failed;
    }
    if (!focus_timeline_bound) {
        for (index = 1u; index < replay_tick_count; ++index) {
            if (replay_ticks[index].focus_active !=
                replay_ticks[index - 1u].focus_active) {
                goto parse_failed;
            }
        }
    } else if (!validate_replay_focus_timeline()) goto parse_failed;
    if (take_line(&cursor) != NULL || *cursor != '\0') goto parse_failed;
    memcpy(replay_sha256, actual_hash, sizeof(replay_sha256));
    HeapFree(GetProcessHeap(), 0, bytes);
    return TRUE;

parse_failed:
    if (replay_ticks) {
        VirtualFree(replay_ticks, 0, MEM_RELEASE);
        replay_ticks = NULL;
    }
    replay_tick_count = 0u;
    if (replay_focus_events) {
        HeapFree(GetProcessHeap(), 0, replay_focus_events);
        replay_focus_events = NULL;
    }
    replay_focus_event_count = 0u;
    if (replay_activation_dts) {
        HeapFree(GetProcessHeap(), 0, replay_activation_dts);
        replay_activation_dts = NULL;
    }
    replay_activation_dt_count = 0u;
    HeapFree(GetProcessHeap(), 0, bytes);
    return FALSE;
}

static BOOL data_user_fixture_ready(void)
{
    WIN32_FIND_DATAA data;
    HANDLE find;
    BOOL found_user = FALSE;
    BYTE actual_hash[32];
    DWORD attributes = GetFileAttributesA("Data\\User");
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0u ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0u) return FALSE;
    find = FindFirstFileA("Data\\User\\*", &data);
    if (find == INVALID_HANDLE_VALUE) return FALSE;
    do {
        if (strcmp(data.cFileName, ".") != 0 &&
            strcmp(data.cFileName, "..") != 0) {
            if (_stricmp(data.cFileName, "user0.dat") != 0 ||
                found_user ||
                (data.dwFileAttributes &
                 (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0u) {
                FindClose(find);
                return FALSE;
            }
            found_user = TRUE;
        }
    } while (FindNextFileA(find, &data));
    if (GetLastError() != ERROR_NO_MORE_FILES) {
        FindClose(find);
        return FALSE;
    }
    FindClose(find);
    return found_user && hash_file("Data\\User\\user0.dat", actual_hash) &&
        memcmp(actual_hash, initial_user_sha256,
               sizeof(initial_user_sha256)) == 0;
}

static BOOL create_observer_event(const char *kind, BOOL preowned,
                                  HANDLE *event_out)
{
    char name[96];
    DWORD process_id = GetCurrentProcessId();
    DWORD create_error;
    int length = snprintf(name, sizeof(name), "Local\\MielObserver%s-%lu",
                          kind, (unsigned long)process_id);
    if (length <= 0 || (size_t)length >= sizeof(name)) return FALSE;
    *event_out = CreateEventA(NULL, TRUE, FALSE, name);
    if (!*event_out) return FALSE;
    create_error = GetLastError();
    if ((create_error == ERROR_ALREADY_EXISTS) != preowned ||
        WaitForSingleObject(*event_out, 0u) != WAIT_TIMEOUT) {
        CloseHandle(*event_out);
        *event_out = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL create_completion_events(void)
{
    char preowned_value[2] = {0};
    BOOL preowned =
        GetEnvironmentVariableA("MIEL_OBSERVER_EVENTS_PREOWNED",
                                preowned_value, sizeof(preowned_value)) == 1u &&
        preowned_value[0] == '1';
    if (create_observer_event("Complete", preowned, &complete_event) &&
        create_observer_event("Failure", preowned, &failure_event) &&
        create_observer_event("Ready", preowned, &ready_event) &&
        create_observer_event("LoginPending", preowned,
                              &login_pending_event) &&
        create_observer_event("LoginActivated", preowned,
                              &login_activation_event) &&
        create_observer_event("NativeDispatchComplete", preowned,
                              &native_dispatch_complete_event)) {
        late_bootstrap_event = CreateEventA(NULL, FALSE, FALSE, NULL);
        if (late_bootstrap_event) return TRUE;
    }

    if (late_bootstrap_event) CloseHandle(late_bootstrap_event);
    if (login_activation_event) CloseHandle(login_activation_event);
    if (native_dispatch_complete_event) CloseHandle(native_dispatch_complete_event);
    if (login_pending_event) CloseHandle(login_pending_event);
    if (ready_event) CloseHandle(ready_event);
    if (failure_event) CloseHandle(failure_event);
    if (complete_event) CloseHandle(complete_event);
    ready_event = NULL;
    late_bootstrap_event = NULL;
    native_dispatch_complete_event = NULL;
    login_activation_event = NULL;
    login_pending_event = NULL;
    failure_event = NULL;
    complete_event = NULL;
    return FALSE;
}

static SIZE_T copy_readable(const void *address, BYTE *output, SIZE_T capacity)
{
    MEMORY_BASIC_INFORMATION information;
    SIZE_T available;
    if (!address || !VirtualQuery(address, &information, sizeof(information)) ||
        information.State != MEM_COMMIT ||
        information.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0u;
    available = (SIZE_T)((const BYTE *)information.BaseAddress +
                         information.RegionSize - (const BYTE *)address);
    if (available > capacity) available = capacity;
    memcpy(output, address, available);
    return available;
}

static BOOL copy_writable(void *address, const void *input, SIZE_T size)
{
    MEMORY_BASIC_INFORMATION information;
    SIZE_T available;
    DWORD writable;
    if (!address || !input || size == 0u ||
        !VirtualQuery(address, &information, sizeof(information)) ||
        information.State != MEM_COMMIT ||
        information.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return FALSE;
    writable = information.Protect &
        (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE |
         PAGE_EXECUTE_WRITECOPY);
    available = (SIZE_T)((BYTE *)information.BaseAddress +
                         information.RegionSize - (BYTE *)address);
    if (!writable || available < size) return FALSE;
    memcpy(address, input, size);
    return TRUE;
}

static DWORD read_u32(const BYTE *bytes, SIZE_T offset)
{
    DWORD value;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static BOOL read_pointer(DWORD object_address, DWORD offset, DWORD *value)
{
    return copy_readable(
        (const void *)(ULONG_PTR)(object_address + offset),
        (BYTE *)value, sizeof(*value)) == sizeof(*value);
}

static BOOL capture_flight(DWORD address, FlightObservation *observation)
{
    BYTE bytes[FLIGHT_CAPTURE_SIZE];
    if (copy_readable((const void *)(ULONG_PTR)address, bytes, sizeof(bytes)) !=
        sizeof(bytes)) return FALSE;
    observation->position[0] = read_u32(bytes, 0x70u);
    observation->position[1] = read_u32(bytes, 0x74u);
    observation->position[2] = read_u32(bytes, 0x78u);
    observation->orientation_wxyz[0] = read_u32(bytes, 0x7cu);
    observation->orientation_wxyz[1] = read_u32(bytes, 0x80u);
    observation->orientation_wxyz[2] = read_u32(bytes, 0x84u);
    observation->orientation_wxyz[3] = read_u32(bytes, 0x88u);
    observation->velocity[0] = read_u32(bytes, 0xecu);
    observation->velocity[1] = read_u32(bytes, 0xf0u);
    observation->velocity[2] = read_u32(bytes, 0xf4u);
    observation->angular_velocity[0] = read_u32(bytes, 0xf8u);
    observation->angular_velocity[1] = read_u32(bytes, 0xfcu);
    observation->angular_velocity[2] = read_u32(bytes, 0x100u);
    observation->propulsion_scale = read_u32(bytes, 0x164u);
    observation->propulsion = read_u32(bytes, 0x168u);
    observation->active = bytes[0x15u];
    observation->fuel = read_u32(bytes, 0x198u);
    observation->integrity = read_u32(bytes, 0x1a0u);
    observation->maximum_integrity = read_u32(bytes, 0x1a4u);
    observation->pending_damage = read_u32(bytes, 0x120u);
    observation->damage_gate_timer = read_u32(bytes, 0x260u);
    observation->controls_enabled = bytes[0x1c0u];
    observation->horizontal_control = read_u32(bytes, 0x1c4u);
    observation->vertical_control = read_u32(bytes, 0x1c8u);
    observation->floor_enabled = bytes[0x1d0u];
    observation->inactive = bytes[0x1e8u];
    return TRUE;
}

static ObserverThread *thread_context(void)
{
    DWORD index;
    LONG thread_id = (LONG)GetCurrentThreadId();
    for (index = 0u; index < THREAD_CONTEXT_COUNT; ++index) {
        if (thread_contexts[index].owner_thread_id == thread_id) {
            return &thread_contexts[index];
        }
    }
    for (index = 0u; index < THREAD_CONTEXT_COUNT; ++index) {
        ObserverThread *context = &thread_contexts[index];
        if (InterlockedCompareExchange(
                &context->owner_thread_id, thread_id, 0) == 0) {
            context->tick = INVALID_ID;
            context->tick_dt_f32_bits = 0u;
            context->controls_sample = INVALID_ID;
            context->controls_dt_f32_bits = 0u;
            context->collision_sample = INVALID_ID;
            context->collision_dt_f32_bits = 0u;
            context->damage_f32_bits = 0u;
            context->damage_integrity_f32_bits = 0u;
            context->damage_terminal = FALSE;
            context->physics_depth = 0u;
            context->physics_overflow = 0u;
            return context;
        }
    }
    return NULL;
}

typedef void *(__attribute__((thiscall)) *ModeResolveFunction)(void *, const char *);
typedef void (__attribute__((thiscall)) *ModeTickFunction)(void *);
typedef BYTE (__attribute__((thiscall)) *ModeSetFunction)(void *, const char *);
typedef void (__attribute__((thiscall)) *SessionLoadFunction)(void *);
typedef void *(__attribute__((cdecl)) *ApplicationGetterFunction)(void);
typedef int (__attribute__((thiscall)) *UserGetIdFunction)(void *);
typedef void (__attribute__((thiscall)) *UserSetIdFunction)(void *, int);
typedef const char *(__attribute__((thiscall)) *UserGetNameFunction)(void *);
typedef void (__attribute__((thiscall)) *UserSetNameFunction)(void *, const char *);
typedef int (__attribute__((thiscall)) *LoginFindFunction)(void *, const char *, BYTE);
typedef void (__attribute__((thiscall)) *LoginClearFunction)(void *);
typedef BYTE (__attribute__((thiscall)) *AirplaneCompleteFunction)(void *);
typedef void (__attribute__((thiscall)) *EngineCommandFunction)(
    void *, DWORD, const char *);

static void emit_session(const char *phase, const char *reason)
{
    char line[TRACE_LINE_SIZE];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"session\",\"sequence\":%lu,"
        "\"channel\":\"session.%s\",\"values\":{"
        "\"scenario\":\"%s\",\"reason\":\"%s\"},"
        "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, phase, replay_scenario, reason,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static BOOL executable_caller_rva(const void *caller, DWORD *rva_out)
{
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS32 nt_headers;
    ULONG_PTR address = (ULONG_PTR)caller;
    if (!base ||
        copy_readable(base, (BYTE *)&dos_header, sizeof(dos_header)) !=
            sizeof(dos_header) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
        dos_header.e_lfanew <= 0 ||
        copy_readable(base + dos_header.e_lfanew, (BYTE *)&nt_headers,
                      sizeof(nt_headers)) != sizeof(nt_headers) ||
        nt_headers.Signature != IMAGE_NT_SIGNATURE ||
        nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        address < (ULONG_PTR)base ||
        address >= (ULONG_PTR)base + nt_headers.OptionalHeader.SizeOfImage) {
        return FALSE;
    }
    *rva_out = (DWORD)(address - (ULONG_PTR)base);
    return TRUE;
}

static void emit_rng(const char *phase, DWORD ordinal, DWORD value,
                     const void *caller)
{
    char line[384];
    char caller_rva[16];
    DWORD rva = 0u;
    DWORD sequence = next_id(&sequence_number);
    if (executable_caller_rva(caller, &rva)) {
        snprintf(caller_rva, sizeof(caller_rva), "\"0x%08lx\"",
                 (unsigned long)rva);
    } else {
        strcpy(caller_rva, "null");
    }
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"rng\",\"sequence\":%lu,"
        "\"channel\":\"rng.%s\",\"tick\":%lu,\"values\":{"
        "\"ordinal\":%lu,\"value\":%lu},"
        "\"diagnostics\":{\"thread_id\":%lu,\"caller_rva\":%s}}\r\n",
        (unsigned long)sequence, phase, (unsigned long)replay_active_tick,
        (unsigned long)ordinal, (unsigned long)value,
        (unsigned long)GetCurrentThreadId(), caller_rva);
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_location_phase_rng(const char *phase, DWORD ordinal,
                                    DWORD value, const char *sha256)
{
    char line[512];
    DWORD sequence = next_id(&diagnostic_sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-location-phase-rng\","
        "\"sequence\":%lu,\"phase\":\"%s\",\"ordinal\":%lu,"
        "\"value\":%lu,\"caller_rva\":\"0x%08lx\","
        "\"count\":%lu,\"sha256\":%s,\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, phase, (unsigned long)ordinal,
        (unsigned long)value, (unsigned long)LOCATION_PHASE_RAND_CALLER_RVA,
        (unsigned long)location_phase_rng_count,
        sha256 ? sha256 : "null", (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static BOOL media_semantics_observation_enabled(void)
{
    LONG state = InterlockedCompareExchange(&session_state, 0, 0);
    return scenario_bounded_observation &&
        state >= SESSION_DISPATCHED && state <= SESSION_READY;
}

static BOOL claim_media_semantics_thread(void)
{
    DWORD current = GetCurrentThreadId();
    DWORD claimed = (DWORD)InterlockedCompareExchange(
        &media_semantics_thread_id, (LONG)current, 0);
    if (claimed == 0u || claimed == current) return TRUE;
    session_fail("media_semantics_thread_contract");
    return FALSE;
}

static void emit_media_audio_start(DWORD call_id, BOOL accepted,
                                   BOOL replaced_active)
{
    char line[768];
    DWORD sequence = next_id(&media_semantics_sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-media-semantics-observation\","
        "\"sequence\":%lu,\"behaviour_id\":\"audio_completion\","
        "\"phase\":\"audio_start\",\"tick\":%lu,\"frame\":%lu,"
        "\"call_id\":%lu,\"site_rva\":\"0x00009fc0\","
        "\"values\":{\"accepted\":%s,\"replaced_active\":%s},"
        "\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, (unsigned long)replay_active_tick,
        (unsigned long)current_frame(), (unsigned long)call_id,
        accepted ? "true" : "false",
        replaced_active ? "true" : "false",
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_media_audio_poll(DWORD call_id, DWORD poll_ordinal,
                                  BOOL complete)
{
    char line[768];
    DWORD sequence = next_id(&media_semantics_sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-media-semantics-observation\","
        "\"sequence\":%lu,\"behaviour_id\":\"audio_completion\","
        "\"phase\":\"audio_poll\",\"tick\":%lu,\"frame\":%lu,"
        "\"call_id\":%lu,\"site_rva\":\"0x0000a650\","
        "\"values\":{\"complete\":%s,\"poll_ordinal\":%lu},"
        "\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, (unsigned long)replay_active_tick,
        (unsigned long)current_frame(), (unsigned long)call_id,
        complete ? "true" : "false", (unsigned long)poll_ordinal,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_media_animation_rng(DWORD call_id, DWORD caller_rva,
                                     DWORD value)
{
    const char *sampling_point =
        caller_rva == ANIMATION_RANDOMFRAME_START_CALLER_RVA ?
            "initial" : "cadence";
    char line[768];
    DWORD sequence = next_id(&media_semantics_sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-media-semantics-observation\","
        "\"sequence\":%lu,\"behaviour_id\":\"randomframe_cadence\","
        "\"phase\":\"rng_draw\",\"tick\":%lu,\"frame\":%lu,"
        "\"call_id\":%lu,\"site_rva\":\"0x%08lx\","
        "\"values\":{\"sampling_point\":\"%s\",\"value\":%lu},"
        "\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, (unsigned long)replay_active_tick,
        (unsigned long)current_frame(), (unsigned long)call_id,
        (unsigned long)caller_rva, sampling_point, (unsigned long)value,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static MediaAudioInstance *find_media_audio_instance(void *instance)
{
    DWORD index;
    for (index = 0u; index < MEDIA_AUDIO_INSTANCE_CAPACITY; ++index) {
        MediaAudioInstance *entry = &media_audio_instances[index];
        if (entry->in_use && entry->instance == instance) return entry;
    }
    return NULL;
}

static MediaAudioInstance *register_media_audio_instance(
    void *instance, DWORD call_id, BOOL *replaced_active
)
{
    DWORD index;
    MediaAudioInstance *entry = find_media_audio_instance(instance);
    MediaAudioInstance *completed = NULL;
    if (replaced_active) *replaced_active = FALSE;
    if (entry) {
        if (replaced_active) *replaced_active = !entry->complete;
    } else {
        for (index = 0u; index < MEDIA_AUDIO_INSTANCE_CAPACITY; ++index) {
            MediaAudioInstance *candidate = &media_audio_instances[index];
            if (!candidate->in_use) {
                entry = candidate;
                break;
            }
            if (candidate->complete && !completed) completed = candidate;
        }
        if (!entry) entry = completed;
    }
    if (!entry) {
        session_fail("media_semantics_audio_instance_capacity");
        return NULL;
    }
    entry->instance = instance;
    entry->call_id = call_id;
    entry->poll_ordinal = 0u;
    entry->complete = FALSE;
    entry->in_use = TRUE;
    return entry;
}

static void * __attribute__((thiscall)) audio_start_hook(
    void *self, DWORD parameter
)
{
    AudioStartFunction original =
        (AudioStartFunction)(ULONG_PTR)audio_start_trampoline;
    void *instance = original(self, parameter);
    DWORD last_error = GetLastError();
    if (media_semantics_observation_enabled() &&
        claim_media_semantics_thread()) {
        DWORD call_id = next_id(&media_audio_call_number);
        BOOL replaced_active = FALSE;
        if (instance) {
            register_media_audio_instance(
                instance, call_id, &replaced_active);
        }
        emit_media_audio_start(call_id, instance != NULL, replaced_active);
    }
    SetLastError(last_error);
    return instance;
}

static BYTE __attribute__((thiscall)) audio_poll_hook(void *self)
{
    AudioPollFunction original =
        (AudioPollFunction)(ULONG_PTR)audio_poll_trampoline;
    BYTE result = original(self);
    DWORD last_error = GetLastError();
    if (media_semantics_observation_enabled() &&
        claim_media_semantics_thread()) {
        MediaAudioInstance *entry = find_media_audio_instance(self);
        if (entry) {
            DWORD ordinal = entry->poll_ordinal++;
            if (result) entry->complete = TRUE;
            emit_media_audio_poll(entry->call_id, ordinal, result != 0u);
        }
    }
    SetLastError(last_error);
    return result;
}

static int __cdecl observer_rand(void)
{
    DWORD last_error = GetLastError();
    const void *caller = __builtin_return_address(0);
    DWORD caller_rva = 0u;
    BOOL caller_is_location_phase =
        executable_caller_rva(caller, &caller_rva) &&
        caller_rva == LOCATION_PHASE_RAND_CALLER_RVA;
    int value;
    if (caller_is_location_phase) {
        if (session_state != SESSION_WAIT_LOGIN ||
            location_phase_rng_complete ||
            location_phase_rng_count >= LOCATION_PHASE_RAND_COUNT) {
            fail_location_phase_rng();
        } else if (!location_phase_rng_seeded) {
            original_srand((unsigned int)replay_flight_activation_seed);
            sha256_init(&location_phase_rng_sha256);
            location_phase_rng_seeded = TRUE;
            emit_location_phase_rng(
                "seed", INVALID_ID, replay_flight_activation_seed, NULL);
        }
    }
    value = original_rand();
    if (caller_is_location_phase && location_phase_rng_seeded &&
        !location_phase_rng_complete &&
        location_phase_rng_count < LOCATION_PHASE_RAND_COUNT) {
        DWORD row[3] = {
            location_phase_rng_count, (DWORD)value, caller_rva
        };
        Sha256Context finalized;
        BYTE digest[32];
        char digest_text[65];
        char quoted_digest[68];
        sha256_update(&location_phase_rng_sha256, (const BYTE *)row,
                      sizeof(row));
        emit_location_phase_rng(
            "draw", location_phase_rng_count, (DWORD)value, NULL);
        ++location_phase_rng_count;
        if (location_phase_rng_count == LOCATION_PHASE_RAND_COUNT) {
            finalized = location_phase_rng_sha256;
            sha256_final(&finalized, digest);
            encode_sha256(digest, digest_text);
            snprintf(quoted_digest, sizeof(quoted_digest), "\"%s\"", digest_text);
            location_phase_rng_complete = TRUE;
            emit_location_phase_rng(
                "complete", INVALID_ID, replay_flight_activation_seed,
                quoted_digest);
        }
    }
    if (flight_activation_rng_open && session_state != SESSION_READY) {
        DWORD rva = 0u;
        DWORD row[3];
        char line[512];
        DWORD diagnostic_sequence;
        int size;
        if (!executable_caller_rva(caller, &rva)) {
            fail_activation_rng();
        } else {
            row[0] = flight_activation_rng_count;
            row[1] = (DWORD)value;
            row[2] = rva;
            sha256_update(&flight_activation_rng_sha256, (const BYTE *)row,
                          sizeof(row));
            diagnostic_sequence = next_id(&diagnostic_sequence_number);
            size = snprintf(
                line, sizeof(line),
                "MVD {\"schema\":1,"
                "\"protocol\":\"miel-vliegt-native-flight-activation-rng\","
                "\"sequence\":%lu,\"phase\":\"draw\",\"ordinal\":%lu,"
                "\"value\":%lu,\"caller_rva\":\"0x%08lx\","
                "\"thread_id\":%lu}\r\n",
                (unsigned long)diagnostic_sequence,
                (unsigned long)flight_activation_rng_count,
                (unsigned long)(DWORD)value, (unsigned long)rva,
                (unsigned long)GetCurrentThreadId());
            if (size > 0 && (size_t)size < sizeof(line)) {
                append_record(line, (DWORD)size);
            }
            ++flight_activation_rng_count;
        }
    }
    if (session_state == SESSION_READY) {
        DWORD ordinal = rng_draw_count++;
        emit_rng("draw", ordinal, (DWORD)value, caller);
    }
    if (media_semantics_observation_enabled() &&
        (caller_rva == ANIMATION_RANDOMFRAME_START_CALLER_RVA ||
         caller_rva == ANIMATION_RANDOMFRAME_CADENCE_CALLER_RVA) &&
        claim_media_semantics_thread()) {
        DWORD ordinal = next_id(&media_animation_rng_number);
        emit_media_animation_rng(ordinal, caller_rva, (DWORD)value);
    }
    SetLastError(last_error);
    return value;
}

static BOOL close_flight_activation_rng(void)
{
    Sha256Context finalized;
    BYTE digest[32];
    char digest_text[65];
    char line[512];
    DWORD diagnostic_sequence;
    int size;
    if (!flight_activation_rng_open) return FALSE;
    flight_activation_rng_open = FALSE;
    finalized = flight_activation_rng_sha256;
    sha256_final(&finalized, digest);
    encode_sha256(digest, digest_text);
    diagnostic_sequence = next_id(&diagnostic_sequence_number);
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-flight-activation-rng\","
        "\"sequence\":%lu,\"phase\":\"complete\",\"count\":%lu,"
        "\"sha256\":\"%s\",\"thread_id\":%lu}\r\n",
        (unsigned long)diagnostic_sequence,
        (unsigned long)flight_activation_rng_count, digest_text,
        (unsigned long)GetCurrentThreadId());
    if (size <= 0 || (size_t)size >= sizeof(line)) return FALSE;
    append_record(line, (DWORD)size);
    return TRUE;
}

static DWORD record_flight_activation_clock(DWORD observed_dt)
{
    DWORD scripted_dt = observed_dt;
    DWORD row[2] = {flight_activation_clock_count, scripted_dt};
    char line[512];
    DWORD diagnostic_sequence = next_id(&diagnostic_sequence_number);
    int size;
    if (!flight_activation_clock_open) return observed_dt;
    if (replay_runtime_state_bound) {
        if (replay_activation_dt_next >= replay_activation_dt_count) {
            fail_activation_clock("flight_activation_clock_tick_overrun");
            return observed_dt;
        }
        scripted_dt = replay_activation_dts[replay_activation_dt_next++];
    } else if (!runtime_state_calibration) {
        fail_activation_clock("flight_activation_clock_unbound_execution");
        return observed_dt;
    }
    row[1] = scripted_dt;
    sha256_update(&flight_activation_clock_sha256, (const BYTE *)row, sizeof(row));
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-flight-activation-clock\","
        "\"sequence\":%lu,\"phase\":\"tick\",\"ordinal\":%lu,"
        "\"observed_dt_f32_bits\":\"0x%08lx\","
        "\"scripted_dt_f32_bits\":\"0x%08lx\",\"thread_id\":%lu}\r\n",
        (unsigned long)diagnostic_sequence,
        (unsigned long)flight_activation_clock_count,
        (unsigned long)observed_dt, (unsigned long)scripted_dt,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
    ++flight_activation_clock_count;
    return scripted_dt;
}

static BOOL close_flight_activation_clock(void)
{
    Sha256Context finalized;
    BYTE digest[32];
    char digest_text[65];
    char line[512];
    DWORD diagnostic_sequence;
    int size;
    if (!flight_activation_clock_open) return FALSE;
    flight_activation_clock_open = FALSE;
    finalized = flight_activation_clock_sha256;
    sha256_final(&finalized, digest);
    encode_sha256(digest, digest_text);
    if (replay_runtime_state_bound &&
        (replay_activation_dt_next != replay_activation_dt_count ||
         memcmp(digest, replay_activation_clock_sha256, sizeof(digest)) != 0)) {
        return FALSE;
    }
    diagnostic_sequence = next_id(&diagnostic_sequence_number);
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-flight-activation-clock\","
        "\"sequence\":%lu,\"phase\":\"complete\",\"count\":%lu,"
        "\"sha256\":\"%s\",\"thread_id\":%lu}\r\n",
        (unsigned long)diagnostic_sequence,
        (unsigned long)flight_activation_clock_count, digest_text,
        (unsigned long)GetCurrentThreadId());
    if (size <= 0 || (size_t)size >= sizeof(line)) return FALSE;
    append_record(line, (DWORD)size);
    return TRUE;
}

static void __cdecl observer_srand(unsigned int seed)
{
    DWORD last_error = GetLastError();
    const void *caller = __builtin_return_address(0);
    original_srand(seed);
    if (session_state == SESSION_READY) {
        DWORD ordinal = rng_seed_count++;
        emit_rng("seed", ordinal, (DWORD)seed, caller);
    }
    SetLastError(last_error);
}

typedef struct ProjectorWindowEvidence {
    HWND window;
    DWORD process_id;
    DWORD window_thread_id;
    LONG client_width;
    LONG client_height;
    BOOL visible;
    BOOL enabled;
    BOOL iconic;
    BOOL top_level;
    BOOL projector_foreground;
    BOOL sink_foreground;
    DWORD candidate_count;
} ProjectorWindowEvidence;

typedef struct WindowSearch {
    DWORD process_id;
    HWND window;
    DWORD count;
    LONG largest_client_area;
} WindowSearch;

static BOOL CALLBACK find_projector_window(HWND window, LPARAM parameter)
{
    WindowSearch *search = (WindowSearch *)parameter;
    DWORD process_id = 0u;
    LONG style;
    RECT client;
    LONG area;
    GetWindowThreadProcessId(window, &process_id);
    if (process_id != search->process_id || !IsWindowVisible(window) ||
        GetWindow(window, GW_OWNER) != NULL) return TRUE;
    style = GetWindowLongA(window, GWL_STYLE);
    if ((style & WS_CHILD) != 0) return TRUE;
    ++search->count;
    if (!GetClientRect(window, &client)) return TRUE;
    area = (client.right - client.left) * (client.bottom - client.top);
    if (area > search->largest_client_area) {
        search->largest_client_area = area;
        search->window = window;
    }
    return TRUE;
}

static BOOL inspect_projector_window(ProjectorWindowEvidence *evidence)
{
    WindowSearch search;
    HWND foreground;
    RECT client;
    LONG style;
    memset(&search, 0, sizeof(search));
    memset(evidence, 0, sizeof(*evidence));
    search.process_id = GetCurrentProcessId();
    if (projector_window) {
        if (!IsWindow(projector_window)) return FALSE;
        search.window = projector_window;
        search.count = 1u;
    } else {
        if (!EnumWindows(find_projector_window, (LPARAM)&search)) return FALSE;
        if (search.count == 0u || !search.window ||
            search.largest_client_area <= 0) return FALSE;
        projector_window = search.window;
    }
    evidence->candidate_count = search.count;
    foreground = GetForegroundWindow();
    evidence->window = projector_window;
    evidence->window_thread_id = GetWindowThreadProcessId(
        projector_window, &evidence->process_id);
    if (!GetClientRect(projector_window, &client)) return FALSE;
    style = GetWindowLongA(projector_window, GWL_STYLE);
    evidence->client_width = client.right - client.left;
    evidence->client_height = client.bottom - client.top;
    evidence->visible = IsWindowVisible(projector_window);
    evidence->enabled = IsWindowEnabled(projector_window);
    evidence->iconic = IsIconic(projector_window);
    evidence->top_level = GetWindow(projector_window, GW_OWNER) == NULL &&
        (style & WS_CHILD) == 0;
    evidence->projector_foreground = foreground == projector_window;
    evidence->sink_foreground = focus_sink_window && foreground == focus_sink_window;
    return evidence->process_id == GetCurrentProcessId() &&
        evidence->window_thread_id != 0u && evidence->visible &&
        evidence->enabled && !evidence->iconic && evidence->top_level &&
        evidence->client_width > 0 && evidence->client_height > 0;
}

static BOOL ensure_focus_sink(void)
{
    if (focus_sink_window && IsWindow(focus_sink_window)) return TRUE;
    focus_sink_window = CreateWindowExA(
        WS_EX_TOOLWINDOW, "STATIC", "MVO Input Focus Sink", WS_POPUP,
        -32000, -32000, 1, 1, projector_window, NULL,
        GetModuleHandleA(NULL), NULL);
    if (!focus_sink_window) return FALSE;
    ShowWindow(focus_sink_window, SW_SHOWNOACTIVATE);
    return TRUE;
}

static BOOL set_window_focus_cross_thread(HWND window)
{
    DWORD process_id = 0u;
    DWORD window_thread = GetWindowThreadProcessId(window, &process_id);
    DWORD caller_thread = GetCurrentThreadId();
    BOOL attached = FALSE;
    BOOL foreground_ok;
    BOOL focus_ok;
    if (!window_thread || process_id != GetCurrentProcessId()) return FALSE;
    if (window_thread != caller_thread) {
        attached = AttachThreadInput(caller_thread, window_thread, TRUE);
        if (!attached) return FALSE;
    }
    foreground_ok = GetForegroundWindow() == window ||
        SetForegroundWindow(window);
    focus_ok = SetFocus(window) != NULL || GetFocus() == window;
    if (attached &&
        !AttachThreadInput(caller_thread, window_thread, FALSE)) {
        return FALSE;
    }
    return foreground_ok && focus_ok;
}

static BOOL set_scripted_focus(BOOL focus_active,
                               ProjectorWindowEvidence *evidence)
{
    if (!inspect_projector_window(evidence)) return FALSE;
    if (focus_active) {
        if (GetForegroundWindow() != projector_window) {
            if (!set_window_focus_cross_thread(projector_window)) return FALSE;
        }
    } else {
        if (!ensure_focus_sink()) return FALSE;
        if (GetForegroundWindow() != focus_sink_window) {
            if (!set_window_focus_cross_thread(focus_sink_window)) return FALSE;
        }
    }
    if (!inspect_projector_window(evidence)) return FALSE;
    return focus_active ? evidence->projector_foreground :
        evidence->sink_foreground && !evidence->projector_foreground;
}

static void emit_input_focus(DWORD target_tick,
                             const ProjectorWindowEvidence *evidence,
                             BOOL focus_active, BOOL valid)
{
    char line[TRACE_LINE_SIZE];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"input\",\"sequence\":%lu,"
        "\"channel\":\"input.focus\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"focus_active\":%s,\"valid\":%s,"
        "\"projector_foreground\":%s,\"sink_foreground\":%s,"
        "\"visible\":%s,\"enabled\":%s,\"iconic\":%s,"
        "\"candidate_count\":%lu},"
        "\"diagnostics\":{\"thread_id\":%lu,\"process_id\":%lu,"
        "\"window_thread_id\":%lu}}\r\n",
        (unsigned long)sequence, (unsigned long)target_tick,
        (unsigned long)current_frame(), focus_active ? "true" : "false",
        valid ? "true" : "false",
        evidence->projector_foreground ? "true" : "false",
        evidence->sink_foreground ? "true" : "false",
        evidence->visible ? "true" : "false",
        evidence->enabled ? "true" : "false",
        evidence->iconic ? "true" : "false",
        (unsigned long)evidence->candidate_count,
        (unsigned long)GetCurrentThreadId(),
        (unsigned long)evidence->process_id,
        (unsigned long)evidence->window_thread_id);
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_input_transition(DWORD target_tick, BYTE from_keys,
                                  BYTE to_keys, DWORD event_count,
                                  DWORD sent_count)
{
    char line[TRACE_LINE_SIZE];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"input\",\"sequence\":%lu,"
        "\"channel\":\"input.transition\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"from_mask\":\"0x%02x\","
        "\"to_mask\":\"0x%02x\",\"event_count\":%lu,"
        "\"sendinput_count\":%lu,\"complete\":%s,"
        "\"input_source\":\"windows_sendinput_scancode\"},"
        "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, (unsigned long)target_tick,
        (unsigned long)current_frame(), (unsigned int)from_keys,
        (unsigned int)to_keys, (unsigned long)event_count,
        (unsigned long)sent_count, sent_count == event_count ? "true" : "false",
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_input_sample(DWORD tick, BYTE expected, BYTE observed,
                              const ProjectorWindowEvidence *evidence,
                              BOOL focus_active,
                              BOOL read_valid, BOOL schedule_match,
                              BOOL focus_valid, BOOL sample_match,
                              BOOL valid)
{
    char line[TRACE_LINE_SIZE];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"input\",\"sequence\":%lu,"
        "\"channel\":\"input.sample\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"expected_mask\":\"0x%02x\","
        "\"observed_mask\":\"0x%02x\",\"read_valid\":%s,"
        "\"schedule_match\":%s,\"sample_match\":%s,"
        "\"focus_active\":%s,\"focus_valid\":%s,\"valid\":%s,"
        "\"foreground\":%s,"
        "\"input_source\":\"native_directinput_after_sendinput\"},"
        "\"diagnostics\":{\"thread_id\":%lu,"
        "\"window_thread_id\":%lu}}\r\n",
        (unsigned long)sequence, (unsigned long)tick,
        (unsigned long)current_frame(), (unsigned int)expected,
        (unsigned int)observed, read_valid ? "true" : "false",
        schedule_match ? "true" : "false",
        sample_match ? "true" : "false",
        focus_active ? "true" : "false", focus_valid ? "true" : "false",
        valid ? "true" : "false",
        evidence->projector_foreground ? "true" : "false",
        (unsigned long)GetCurrentThreadId(),
        (unsigned long)evidence->window_thread_id);
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static BYTE sampled_key_mask(DWORD mode_address, BOOL *read_ok)
{
    BYTE keys[6];
    BYTE mask = 0u;
    DWORD index;
    *read_ok = copy_readable((const void *)(ULONG_PTR)(mode_address + 0x70u),
                             keys, sizeof(keys)) == sizeof(keys);
    if (!*read_ok) return 0u;
    for (index = 0u; index < sizeof(keys); ++index) {
        if (keys[index] != 0u) mask |= (BYTE)(1u << index);
    }
    return mask;
}

/* Force keys in os_input_release_lag to read as released in the game's polled
 * keyboard buffer (mode+0x70).  This runs before verify_replay_key_sample and
 * before the game's own input processing, ensuring both the verify check and
 * the game logic see the correct key state even when SendInput KEYUP events
 * are lost in FEX-emu/Wine's input queue.  The mask persists until
 * send_replay_keys clears it on re-press. */
static void force_release_lag_keys(DWORD mode_address)
{
    BYTE keys[6];
    DWORD index;
    BOOL any_cleared = FALSE;
    if (os_input_release_lag == 0u) return;
    if (copy_readable((const void *)(ULONG_PTR)(mode_address + 0x70u),
                      keys, sizeof(keys)) != sizeof(keys)) return;
    for (index = 0u; index < 6u; ++index) {
        if ((os_input_release_lag & (BYTE)(1u << index)) != 0u &&
            keys[index] != 0u) {
            keys[index] = 0u;
            any_cleared = TRUE;
        }
    }
    if (any_cleared) {
        copy_writable((void *)(ULONG_PTR)(mode_address + 0x70u),
                      keys, sizeof(keys));
    }
}

static BOOL send_replay_keys(DWORD target_tick, BYTE desired_keys,
                             BOOL focus_active)
{
    static const WORD scan_codes[6] = {0x4bu, 0x4du, 0x48u, 0x50u, 0x2au, 0x1du};
    static const BYTE extended[6] = {1u, 1u, 1u, 1u, 0u, 0u};
    INPUT inputs[12];
    ProjectorWindowEvidence evidence;
    BYTE physical_keys = focus_active ? desired_keys : 0u;
    BYTE changed = (BYTE)(os_input_keys ^ physical_keys);
    DWORD count = 0u;
    DWORD index;
    DWORD sent;
    BOOL change_focus = !os_input_initialized ||
        os_input_target_focus != (BYTE)(focus_active != FALSE);
    BOOL focus_valid = FALSE;
    memset(&evidence, 0, sizeof(evidence));
    if ((desired_keys & ~REPLAY_KEY_MASK) != 0u) return FALSE;
    if (focus_active) {
        if (change_focus) focus_valid = set_scripted_focus(TRUE, &evidence);
        else focus_valid = inspect_projector_window(&evidence) &&
            evidence.projector_foreground;
        if (!focus_valid) {
            emit_input_focus(target_tick, &evidence, TRUE, FALSE);
            return FALSE;
        }
    }
    memset(inputs, 0, sizeof(inputs));
    for (index = 0u; index < 6u; ++index) {
        BYTE bit = (BYTE)(1u << index);
        if ((changed & bit) != 0u && (physical_keys & bit) == 0u) {
            inputs[count].type = INPUT_KEYBOARD;
            inputs[count].ki.wScan = scan_codes[index];
            inputs[count].ki.dwFlags = KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP |
                (extended[index] ? KEYEVENTF_EXTENDEDKEY : 0u);
            ++count;
        }
    }
    for (index = 0u; index < 6u; ++index) {
        BYTE bit = (BYTE)(1u << index);
        if ((changed & bit) != 0u && (physical_keys & bit) != 0u) {
            inputs[count].type = INPUT_KEYBOARD;
            inputs[count].ki.wScan = scan_codes[index];
            inputs[count].ki.dwFlags = KEYEVENTF_SCANCODE |
                (extended[index] ? KEYEVENTF_EXTENDEDKEY : 0u);
            ++count;
        }
    }
    os_input_maybe_down |= physical_keys;
    sent = count == 0u ? 0u : SendInput(count, inputs, sizeof(INPUT));
    emit_input_transition(target_tick, os_input_keys, physical_keys, count, sent);
    if (sent != count) return FALSE;
    /* DirectInput drains an asynchronously-injected KEYEVENTF_KEYUP one tick
     * behind SendInput.  Capture the bits this transition just released so
     * force_release_lag_keys can zero them in the game's keyboard buffer on
     * the following tick.  On FEX-emu/ARM64 the KEYUP may never drain at
     * all, so force_release_lag_keys zeroes these bits directly each tick.
     * The mask persists until the key is re-pressed in the replay schedule. */
    {
        BYTE new_releases = (BYTE)(os_input_keys & ~physical_keys);
        if (new_releases != 0u) {
            os_input_release_lag |= new_releases;
        }
       /* Clear release-lag for keys that are now pressed again so the
         * retry below does not send a spurious KEYUP that would undo the
         * press. */
        os_input_release_lag = (BYTE)(os_input_release_lag & ~physical_keys);
    }
    /* Re-send KEYUP for keys whose release has not yet propagated to
     * DirectInput.  On FEX-emu/ARM64, a single SendInput KEYUP may take
     * many ticks to drain through Wine's input queue to DirectInput's
     * GetDeviceState.  Re-sending every tick while the release-lag budget
     * is active gives the event multiple opportunities to propagate,
     * rather than relying on a single injection that can be lost. */
    if (os_input_release_lag != 0u) {
        INPUT retry_inputs[6];
        DWORD retry_count = 0u;
        memset(retry_inputs, 0, sizeof(retry_inputs));
        for (index = 0u; index < 6u; ++index) {
            BYTE bit = (BYTE)(1u << index);
            if ((os_input_release_lag & bit) != 0u) {
                retry_inputs[retry_count].type = INPUT_KEYBOARD;
                retry_inputs[retry_count].ki.wScan = scan_codes[index];
                retry_inputs[retry_count].ki.dwFlags = KEYEVENTF_SCANCODE |
                    KEYEVENTF_KEYUP |
                    (extended[index] ? KEYEVENTF_EXTENDEDKEY : 0u);
                ++retry_count;
            }
        }
        if (retry_count > 0u) {
            SendInput(retry_count, retry_inputs, sizeof(INPUT));
        }
    }
    os_input_keys = physical_keys;
    os_input_maybe_down = physical_keys;
    if (!focus_active) {
        if (change_focus) focus_valid = set_scripted_focus(FALSE, &evidence);
        else focus_valid = inspect_projector_window(&evidence) &&
            evidence.sink_foreground && !evidence.projector_foreground;
        if (!focus_valid) {
            emit_input_focus(target_tick, &evidence, FALSE, FALSE);
            return FALSE;
        }
    }
    emit_input_focus(target_tick, &evidence, focus_active, TRUE);
    os_input_scripted_keys = desired_keys;
    os_input_target_focus = (BYTE)(focus_active != FALSE);
    os_input_target_tick = target_tick;
    os_input_initialized = TRUE;
    input_injected = TRUE;
    return TRUE;
}

static ULONGLONG focus_elapsed_ns(LARGE_INTEGER counter)
{
    ULONGLONG ticks;
    ULONGLONG frequency;
    ULONGLONG seconds;
    ULONGLONG remainder;
    if (counter.QuadPart < replay_focus_episode_origin.QuadPart ||
        replay_focus_clock_frequency.QuadPart <= 0) {
        return 0xffffffffffffffffull;
    }
    ticks = (ULONGLONG)(
        counter.QuadPart - replay_focus_episode_origin.QuadPart);
    frequency = (ULONGLONG)replay_focus_clock_frequency.QuadPart;
    seconds = ticks / frequency;
    remainder = ticks % frequency;
    if (seconds > 0xffffffffffffffffull / 1000000000ull) {
        return 0xffffffffffffffffull;
    }
    return seconds * 1000000000ull +
        (remainder * 1000000000ull) / frequency;
}

static void emit_focus_timeline_event(const ReplayFocusEvent *event,
                                      ULONGLONG applied_offset_ns)
{
    char line[1024];
    char scenario_hash[65];
    char timeline_hash[65];
    DWORD sequence = next_id(&diagnostic_sequence_number);
    ULONGLONG lateness = applied_offset_ns >= event->offset_ns
        ? applied_offset_ns - event->offset_ns : 0u;
    encode_sha256(replay_scenario_sha256, scenario_hash);
    encode_sha256(replay_focus_timeline_sha256, timeline_hash);
    int size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-focus-timeline\","
        "\"sequence\":%lu,\"phase\":\"event\","
        "\"scenario\":\"%s\",\"scenario_sha256\":\"%s\","
        "\"timeline_sha256\":\"%s\","
        "\"clock\":\"query_performance_counter\","
        "\"origin\":\"episode-focus-loss\","
        "\"ordinal\":%lu,\"episode\":%lu,\"tick\":%lu,"
        "\"active\":%s,\"scheduled_offset_ns\":%llu,"
        "\"applied_offset_ns\":%llu,\"lateness_ns\":%llu,"
        "\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, replay_scenario, scenario_hash, timeline_hash,
        (unsigned long)event->ordinal, (unsigned long)event->episode,
        (unsigned long)event->tick, event->active ? "true" : "false",
        (unsigned long long)event->offset_ns,
        (unsigned long long)applied_offset_ns,
        (unsigned long long)lateness,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) {
        append_record(line, (DWORD)size);
    }
}

static void emit_focus_timeline_phase(const char *phase, DWORD episode)
{
    char line[768];
    char scenario_hash[65];
    char timeline_hash[65];
    DWORD sequence = next_id(&diagnostic_sequence_number);
    encode_sha256(replay_scenario_sha256, scenario_hash);
    encode_sha256(replay_focus_timeline_sha256, timeline_hash);
    int size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-focus-timeline\","
        "\"sequence\":%lu,\"phase\":\"%s\","
        "\"scenario\":\"%s\",\"scenario_sha256\":\"%s\","
        "\"timeline_sha256\":\"%s\","
        "\"clock\":\"query_performance_counter\","
        "\"origin\":\"episode-focus-loss\","
        "\"episode\":%lu,\"event_count\":%lu,\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, phase, replay_scenario, scenario_hash,
        timeline_hash, (unsigned long)episode,
        (unsigned long)replay_focus_event_count,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) {
        append_record(line, (DWORD)size);
    }
}

static BOOL wait_for_focus_offset(ULONGLONG target_ns,
                                  ULONGLONG *applied_offset_ns)
{
    for (;;) {
        LARGE_INTEGER now;
        ULONGLONG elapsed;
        ULONGLONG remaining;
        DWORD wait_ms;
        if (WaitForSingleObject(replay_focus_stop_event, 0u) ==
            WAIT_OBJECT_0) return FALSE;
        if (!QueryPerformanceCounter(&now)) return FALSE;
        elapsed = focus_elapsed_ns(now);
        if (elapsed == 0xffffffffffffffffull) return FALSE;
        if (elapsed >= target_ns) {
            *applied_offset_ns = elapsed;
            return elapsed - target_ns <= FOCUS_TIMELINE_LATE_LIMIT_NS;
        }
        remaining = target_ns - elapsed;
        wait_ms = remaining > 10000000ull ? 10u :
            remaining > 1000000ull ? (DWORD)(remaining / 1000000ull) : 0u;
        Sleep(wait_ms);
    }
}

static void destroy_focus_sink_on_owner_thread(void)
{
    DWORD process_id = 0u;
    DWORD owner_thread;
    if (!focus_sink_window || !IsWindow(focus_sink_window)) {
        focus_sink_window = NULL;
        return;
    }
    owner_thread = GetWindowThreadProcessId(
        focus_sink_window, &process_id);
    if (process_id == GetCurrentProcessId() &&
        owner_thread == GetCurrentThreadId() &&
        DestroyWindow(focus_sink_window)) {
        focus_sink_window = NULL;
    }
}

static DWORD WINAPI replay_focus_scheduler_thread(void *unused)
{
    HANDLE waits[2] = {replay_focus_stop_event, replay_focus_arm_event};
    (void)unused;
    for (;;) {
        DWORD wait = WaitForMultipleObjects(2u, waits, FALSE, INFINITE);
        DWORD event_index;
        DWORD episode;
        BOOL episode_loss_applied;
        if (wait == WAIT_OBJECT_0) {
            destroy_focus_sink_on_owner_thread();
            return 0u;
        }
        if (wait != WAIT_OBJECT_0 + 1u ||
            InterlockedCompareExchange(
                &replay_focus_scheduler_state, 2, 1) != 1) {
            session_fail("focus_timeline_worker_state");
            destroy_focus_sink_on_owner_thread();
            return 1u;
        }
        event_index = (DWORD)InterlockedCompareExchange(
            &replay_focus_next_event, 0, 0);
        if (event_index >= replay_focus_event_count ||
            replay_focus_events[event_index].active ||
            replay_focus_events[event_index].episode !=
                replay_focus_armed_episode) {
            session_fail("focus_timeline_worker_order");
            destroy_focus_sink_on_owner_thread();
            return 1u;
        }
        episode = replay_focus_armed_episode;
        episode_loss_applied = FALSE;
        emit_focus_timeline_phase("start", episode);
        for (;;) {
            ReplayFocusEvent *event;
            ULONGLONG applied_offset_ns;
            event_index = (DWORD)InterlockedCompareExchange(
                &replay_focus_next_event, 0, 0);
            if (event_index >= replay_focus_event_count) {
                session_fail("focus_timeline_missing_regain");
                destroy_focus_sink_on_owner_thread();
                return 1u;
            }
            event = &replay_focus_events[event_index];
            if (event->ordinal != event_index ||
                event->episode != episode) {
                session_fail("focus_timeline_late_or_out_of_order");
                SetEvent(replay_focus_applied_event);
                destroy_focus_sink_on_owner_thread();
                return 1u;
            }
            if (!episode_loss_applied) {
                if (event->active || event->offset_ns != 0u) {
                    session_fail("focus_timeline_late_or_out_of_order");
                    SetEvent(replay_focus_applied_event);
                    destroy_focus_sink_on_owner_thread();
                    return 1u;
                }
                applied_offset_ns = 0u;
            } else if (!wait_for_focus_offset(
                           event->offset_ns, &applied_offset_ns)) {
                session_fail("focus_timeline_late_or_out_of_order");
                SetEvent(replay_focus_applied_event);
                destroy_focus_sink_on_owner_thread();
                return 1u;
            }
            replay_next_tick = event->tick;
            if (!send_replay_keys(
                    event->tick, replay_ticks[event->tick].keys,
                    event->active != 0u)) {
                session_fail("focus_timeline_windows_input");
                SetEvent(replay_focus_applied_event);
                destroy_focus_sink_on_owner_thread();
                return 1u;
            }
            if (!episode_loss_applied) {
                if (!QueryPerformanceCounter(&replay_focus_episode_origin)) {
                    session_fail("focus_timeline_clock_origin");
                    SetEvent(replay_focus_applied_event);
                    destroy_focus_sink_on_owner_thread();
                    return 1u;
                }
                episode_loss_applied = TRUE;
            } else {
                LARGE_INTEGER applied_counter;
                if (!QueryPerformanceCounter(&applied_counter)) {
                    session_fail("focus_timeline_clock_sample");
                    SetEvent(replay_focus_applied_event);
                    destroy_focus_sink_on_owner_thread();
                    return 1u;
                }
                applied_offset_ns = focus_elapsed_ns(applied_counter);
                if (applied_offset_ns == 0xffffffffffffffffull ||
                    applied_offset_ns < event->offset_ns ||
                    applied_offset_ns - event->offset_ns >
                        FOCUS_TIMELINE_LATE_LIMIT_NS) {
                    emit_focus_timeline_event(event, applied_offset_ns);
                    session_fail("focus_timeline_late_or_out_of_order");
                    SetEvent(replay_focus_applied_event);
                    destroy_focus_sink_on_owner_thread();
                    return 1u;
                }
            }
            replay_focus_applied_ordinal = event->ordinal;
            replay_focus_applied_offset_ns = applied_offset_ns;
            emit_focus_timeline_event(event, applied_offset_ns);
            InterlockedIncrement(&replay_focus_next_event);
            SetEvent(replay_focus_applied_event);
            if (event->active) break;
        }
        emit_focus_timeline_phase("complete", episode);
        destroy_focus_sink_on_owner_thread();
        replay_focus_armed_episode = INVALID_ID;
        InterlockedExchange(&replay_focus_scheduler_state, 0);
    }
}

static BOOL arm_replay_focus_timeline(DWORD target_tick)
{
    DWORD event_index = (DWORD)InterlockedCompareExchange(
        &replay_focus_next_event, 0, 0);
    ReplayFocusEvent *event;
    DWORD wait;
    if (event_index >= replay_focus_event_count) return FALSE;
    event = &replay_focus_events[event_index];
    if (event->ordinal != event_index || event->tick != target_tick ||
        event->active || event->offset_ns != 0u ||
        InterlockedCompareExchange(
            &replay_focus_scheduler_state, 1, 0) != 0) {
        return FALSE;
    }
    replay_focus_armed_episode = event->episode;
    replay_focus_applied_ordinal = INVALID_ID;
    replay_focus_applied_offset_ns = 0u;
    ResetEvent(replay_focus_applied_event);
    if (!SetEvent(replay_focus_arm_event)) {
        InterlockedExchange(&replay_focus_scheduler_state, 0);
        return FALSE;
    }
    wait = WaitForSingleObject(
        replay_focus_applied_event, FOCUS_TIMELINE_ARM_WAIT_MS);
    return wait == WAIT_OBJECT_0 &&
        session_state != SESSION_FAILED &&
        replay_focus_applied_ordinal == event_index &&
        os_input_target_tick == target_tick &&
        os_input_target_focus == 0u;
}

static BOOL start_replay_focus_scheduler(void)
{
    HANDLE thread;
    if (replay_focus_event_count == 0u) return TRUE;
    if (!QueryPerformanceFrequency(&replay_focus_clock_frequency) ||
        replay_focus_clock_frequency.QuadPart <= 0) return FALSE;
    replay_focus_arm_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    replay_focus_applied_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    replay_focus_stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!replay_focus_arm_event || !replay_focus_applied_event ||
        !replay_focus_stop_event) return FALSE;
    thread = CreateThread(
        NULL, 0u, replay_focus_scheduler_thread, NULL, 0u, NULL);
    if (!thread) return FALSE;
    CloseHandle(thread);
    return TRUE;
}

static BOOL verify_replay_key_sample(DWORD mode_address, const ReplayTick *tick)
{
    ProjectorWindowEvidence evidence;
    BOOL read_ok;
    BYTE expected = tick->focus_active ? tick->keys : 0u;
    BOOL identity_valid = inspect_projector_window(&evidence);
    BOOL focus_valid = identity_valid && (tick->focus_active ?
        evidence.projector_foreground :
        evidence.sink_foreground && !evidence.projector_foreground);
    BYTE observed = sampled_key_mask(mode_address, &read_ok);
    BOOL schedule_match = os_input_initialized &&
        os_input_target_tick == tick->tick &&
        os_input_target_focus == tick->focus_active &&
        os_input_scripted_keys == tick->keys && os_input_keys == expected;
    BYTE missing = (BYTE)(expected & ~observed);
    BYTE extra = (BYTE)(observed & ~expected);
    /* Tolerate bits in os_input_release_lag as a fallback; normally
     * force_release_lag_keys has already zeroed them in the buffer.
     * Missing presses (expected but not yet observed) are never tolerated. */
    BOOL release_lag_ok = missing == 0u &&
        (BYTE)(extra & ~os_input_release_lag) == 0u;
    BOOL sample_match = read_ok &&
        (observed == expected || release_lag_ok);
    BOOL valid = focus_valid && read_ok && schedule_match && sample_match;
    emit_input_sample(tick->tick, expected, observed, &evidence,
                      tick->focus_active != 0u, read_ok, schedule_match,
                     focus_valid, sample_match, valid);
    return valid;
}

static BOOL release_replay_keys(void)
{
    static const WORD scan_codes[6] = {0x4bu, 0x4du, 0x48u, 0x50u, 0x2au, 0x1du};
    static const BYTE extended[6] = {1u, 1u, 1u, 1u, 0u, 0u};
    INPUT inputs[6];
    BYTE release_bits[6];
    DWORD count = 0u;
    DWORD index;
    DWORD sent;
    BYTE from_keys = os_input_maybe_down;
    BYTE remaining_keys;
    memset(inputs, 0, sizeof(inputs));
    memset(release_bits, 0, sizeof(release_bits));
    for (index = 0u; index < 6u; ++index) {
        BYTE bit = (BYTE)(1u << index);
        if ((os_input_maybe_down & bit) != 0u) {
            release_bits[count] = bit;
            inputs[count].type = INPUT_KEYBOARD;
            inputs[count].ki.wScan = scan_codes[index];
            inputs[count].ki.dwFlags = KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP |
                (extended[index] ? KEYEVENTF_EXTENDEDKEY : 0u);
            ++count;
        }
    }
    sent = count == 0u ? 0u : SendInput(count, inputs, sizeof(INPUT));
    remaining_keys = from_keys;
    for (index = 0u; index < sent && index < count; ++index) {
        remaining_keys = (BYTE)(remaining_keys & ~release_bits[index]);
    }
    if (count != 0u) {
        emit_input_transition(
            replay_active_tick, from_keys, remaining_keys, count, sent);
    }
    os_input_keys = (BYTE)(os_input_keys & remaining_keys);
    os_input_maybe_down = remaining_keys;
    if (sent != count) return FALSE;
    os_input_keys = 0u;
    if (projector_window && IsWindow(projector_window)) {
        (void)set_window_focus_cross_thread(projector_window);
    }
    destroy_focus_sink_on_owner_thread();
    return TRUE;
}

static BOOL post_natural_edge_input_is_suspended(void)
{
    return InterlockedCompareExchange(
        &post_natural_edge_input_suspended, 0, 0) != 0;
}

static BOOL suspend_post_natural_edge_input_contract(DWORD tick)
{
    char line[768];
    DWORD sequence;
    LONG boundary_state;
    int size;
    if (!post_natural_edge_input_is_suspended()) return FALSE;
    boundary_state = InterlockedCompareExchange(
        &post_natural_edge_input_boundary_state, 1, 0);
    if (boundary_state == 2) return TRUE;
    if (boundary_state != 0) return FALSE;
    if (!release_replay_keys()) {
        InterlockedExchange(&post_natural_edge_input_boundary_state, 0);
        return FALSE;
    }
    os_input_scripted_keys = 0u;
    os_input_target_focus = 1u;
    os_input_target_tick = tick;
    replay_active_keys = 0u;
    sequence = next_id(&diagnostic_sequence_number);
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-input-contract\","
        "\"record\":\"input_contract_suspended\","
        "\"sequence\":%lu,\"tick\":%lu,"
        "\"reason\":\"natural_transition_observed\","
        "\"evidence_scope\":\"POST_NATURAL_EDGE_DIAGNOSTIC_ONLY\","
        "\"input_sample_verification\":false,"
        "\"parity_eligible\":false,"
        "\"natural_transition_evidence\":false,"
        "\"state_writes\":false,"
        "\"observer_keys_released\":true,"
        "\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, (unsigned long)tick,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line) &&
        append_record_checked(line, (DWORD)size)) {
        InterlockedExchange(&post_natural_edge_input_boundary_state, 2);
        return TRUE;
    }
    InterlockedExchange(&post_natural_edge_input_boundary_state, 0);
    return FALSE;
}

static BOOL send_login_submit_input(void)
{
    INPUT inputs[2];
    memset(inputs, 0, sizeof(inputs));
    inputs[0].type = INPUT_KEYBOARD;
    inputs[0].ki.wScan = 0x1cu;
    inputs[0].ki.dwFlags = KEYEVENTF_SCANCODE;
    inputs[1] = inputs[0];
    inputs[1].ki.dwFlags |= KEYEVENTF_KEYUP;
    return SendInput(2u, inputs, sizeof(INPUT)) == 2u;
}

static BOOL send_barn_escape_input(void)
{
    INPUT inputs[2];
    ProjectorWindowEvidence evidence;
    if (!inspect_projector_window(&evidence) ||
        evidence.window_thread_id != GetCurrentThreadId()) return FALSE;
    if (GetForegroundWindow() != projector_window) {
        SetForegroundWindow(projector_window);
        SetFocus(projector_window);
    }
    memset(inputs, 0, sizeof(inputs));
    inputs[0].type = INPUT_KEYBOARD;
    inputs[0].ki.wScan = 0x01u;
    inputs[0].ki.dwFlags = KEYEVENTF_SCANCODE;
    inputs[1] = inputs[0];
    inputs[1].ki.dwFlags |= KEYEVENTF_KEYUP;
    return SendInput(2u, inputs, sizeof(INPUT)) == 2u;
}

static BOOL send_bootstrap_faster_input(BOOL down)
{
    INPUT input;
    ProjectorWindowEvidence evidence;
    if (bootstrap_faster_input_down == down) return TRUE;
    if (!inspect_projector_window(&evidence) ||
        evidence.window_thread_id != GetCurrentThreadId()) return FALSE;
    if (down && GetForegroundWindow() != projector_window) {
        SetForegroundWindow(projector_window);
        SetFocus(projector_window);
    }
    memset(&input, 0, sizeof(input));
    input.type = INPUT_KEYBOARD;
    input.ki.wScan = 0x2au;
    input.ki.dwFlags = KEYEVENTF_SCANCODE |
        (down ? 0u : KEYEVENTF_KEYUP);
    if (SendInput(1u, &input, sizeof(INPUT)) != 1u) return FALSE;
    bootstrap_faster_input_down = down;
    return TRUE;
}

static BOOL send_projector_click(LONG client_x, LONG client_y)
{
    ProjectorWindowEvidence evidence;
    RECT client;
    POINT point;
    LPARAM position;
    point.x = client_x;
    point.y = client_y;
    if (!inspect_projector_window(&evidence) ||
        evidence.window_thread_id != GetCurrentThreadId() ||
        !GetClientRect(projector_window, &client) ||
        client.right - client.left < 640 || client.bottom - client.top < 480 ||
        !ClientToScreen(projector_window, &point)) return FALSE;
    if (GetForegroundWindow() != projector_window) {
        SetForegroundWindow(projector_window);
        SetFocus(projector_window);
    }
    if (!SetCursorPos(point.x, point.y)) return FALSE;
    position = MAKELPARAM((WORD)client_x, (WORD)client_y);
    return PostMessageA(projector_window, WM_MOUSEMOVE, 0u, position) &&
        PostMessageA(projector_window, WM_LBUTTONDOWN, MK_LBUTTON, position) &&
        PostMessageA(projector_window, WM_LBUTTONUP, 0u, position);
}

static void session_fail(const char *reason)
{
    if (session_state == SESSION_FAILED || session_state == SESSION_COMPLETE) return;
    if (replay_focus_stop_event) SetEvent(replay_focus_stop_event);
    send_bootstrap_faster_input(FALSE);
    (void)release_replay_keys();
    session_state = SESSION_FAILED;
    emit_natural_session("complete", "FAIL");
    emit_session("failed", reason);
    write_marker("SCENARIO_FAILED");
    flush_trace();
    if (failure_event) SetEvent(failure_event);
}

static BOOL native_dispatch_emit_line(
    const char *line, DWORD size, void *context
)
{
    (void)context;
    return append_record_durable_checked(line, size);
}

static BOOL normalize_native_dispatch_failure_reason(
    const char *reason, char *output, size_t capacity
)
{
    static const char prefix[] = "native_dispatch_";
    size_t used = sizeof(prefix) - 1u;
    BOOL separator = FALSE;
    const unsigned char *cursor = (const unsigned char *)reason;
    if (!reason || !*reason || !output || capacity <= used + 1u) return FALSE;
    memcpy(output, prefix, used);
    while (*cursor) {
        unsigned char value = *cursor++;
        if (value < 0x20u || value > 0x7eu) return FALSE;
        if ((value >= 'A' && value <= 'Z') ||
            (value >= 'a' && value <= 'z') ||
            (value >= '0' && value <= '9')) {
            if (used + 1u >= capacity) return FALSE;
            output[used++] = value >= 'A' && value <= 'Z' ?
                (char)(value + ('a' - 'A')) : (char)value;
            separator = FALSE;
        } else if (!separator) {
            if (used + 1u >= capacity) return FALSE;
            output[used++] = '_';
            separator = TRUE;
        }
    }
    if (separator && used > sizeof(prefix) - 1u) --used;
    if (used == sizeof(prefix) - 1u) return FALSE;
    output[used] = '\0';
    return TRUE;
}

static void native_dispatch_fail(const char *reason, void *context)
{
    char normalized[192];
    (void)context;
    if (!normalize_native_dispatch_failure_reason(
            reason, normalized, sizeof(normalized))) {
        strcpy(normalized, "native_dispatch_producer_contract");
    }
    session_fail(normalized);
}

static BOOL native_dispatch_capture_completed(
    DWORD native_process_id, const char *capture_session_id, void *context
)
{
    (void)context;
    if (!native_capture_driver_complete()) return FALSE;
    if (!native_dispatch_shared_identity || !native_dispatch_complete_event ||
        native_process_id != GetCurrentProcessId() || !capture_session_id ||
        native_dispatch_shared_identity->schema != 1u ||
        native_dispatch_shared_identity->native_process_id != native_process_id ||
        InterlockedCompareExchange(
            &native_dispatch_shared_identity->ready,0,0) != 1 ||
        strcmp(native_dispatch_shared_identity->capture_session_id,
               capture_session_id) != 0 ||
        InterlockedCompareExchange(
            &native_dispatch_shared_identity->capture_complete,1,0) != 0) {
        return FALSE;
    }
    MemoryBarrier();
    return SetEvent(native_dispatch_complete_event);
}

static void fail_activation_rng(void)
{
    session_fail("flight_activation_rng_caller_contract");
}

static void fail_activation_clock(const char *reason)
{
    session_fail(reason);
}

static void fail_location_phase_rng(void)
{
    session_fail("location_phase_rng_boundary_contract");
}

static void emit_runtime_state_field(const char *phase, DWORD index,
                                     DWORD value)
{
    const RuntimeStateField *field = &RUNTIME_STATE_FIELDS[index];
    char line[512];
    DWORD sequence = next_id(&diagnostic_sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-initial-state\","
        "\"sequence\":%lu,\"phase\":\"%s\",\"index\":%lu,"
        "\"name\":\"flight.%s\",\"encoding\":\"%s\","
        "\"access_mode\":\"%s\","
        "\"value_hex\":\"%0*lx\",\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, phase, (unsigned long)index, field->name,
        field->width == 1u ? "u8" : "f32le-bits",
        field->writable ? "write-readback" : "compare-only",
        field->width == 1u ? 2 : 8, (unsigned long)value,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_runtime_state_complete(const char *phase)
{
    char line[384];
    DWORD sequence = next_id(&diagnostic_sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-initial-state\","
        "\"sequence\":%lu,\"phase\":\"%s_complete\","
        "\"field_count\":%lu,\"replay_bound\":%s,\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, phase,
        (unsigned long)RUNTIME_STATE_FIELD_COUNT,
        replay_runtime_state_bound ? "true" : "false",
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static BOOL prepare_runtime_initial_state(DWORD manager_node)
{
    DWORD manager_address = manager_node - 0x108u;
    DWORD current = 0u, pending = 0u, manager_flight = 0u;
    DWORD flight_address = 0u;
    DWORD primary_vtable = 0u, secondary_vtable = 0u;
    DWORD index;
    void *resolved = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
        (void *)(ULONG_PTR)manager_address, "mode_fly");
    ObserverThread *context = thread_context();
    if (!resolved || !context || context->physics_depth != 0u ||
        InterlockedCompareExchange(&manager_render_active, 0, 0) != 0 ||
        InterlockedCompareExchange(&engine_thread_id, 0, 0) !=
            (LONG)GetCurrentThreadId() ||
        !read_pointer(manager_address, 0x18cu, &current) ||
        !read_pointer(manager_address, 0x190u, &pending) ||
        !read_pointer(manager_address, 0x154u, &manager_flight) ||
        current != (DWORD)(ULONG_PTR)resolved || pending != 0u ||
        !read_pointer(current, 0x64u, &flight_address) || flight_address == 0u ||
        flight_address != manager_flight ||
        !read_pointer(flight_address, 0u, &primary_vtable) ||
        !read_pointer(flight_address, 0x28u, &secondary_vtable) ||
        primary_vtable != 0x0044c9fcu || secondary_vtable != 0x0044c9f8u) {
        return FALSE;
    }
    for (index = 0u; index < UDSP_THREAD_CONTEXT_COUNT; ++index) {
        if (udsp_threads[index].owner_thread_id == (LONG)GetCurrentThreadId() &&
            udsp_threads[index].depth != 0u) {
            return FALSE;
        }
    }
    if (!replay_runtime_state_bound) {
        if (!runtime_state_calibration) return FALSE;
        for (index = 0u; index < RUNTIME_STATE_FIELD_COUNT; ++index) {
            const RuntimeStateField *field = &RUNTIME_STATE_FIELDS[index];
            DWORD value = 0u;
            if (copy_readable(
                    (const void *)(ULONG_PTR)(flight_address + field->offset),
                    (BYTE *)&value, field->width) != field->width) {
                return FALSE;
            }
            emit_runtime_state_field("calibration", index, value);
        }
        emit_runtime_state_complete("calibration");
        return TRUE;
    }
    /* Compare every lifecycle-derived/cache-sensitive scalar before the sole
     * reviewed write.  A mismatch is evidence that this replay targets a
     * different native bootstrap and must abort, not a reason to widen writes. */
    for (index = 0u; index < RUNTIME_STATE_FIELD_COUNT; ++index) {
        const RuntimeStateField *field = &RUNTIME_STATE_FIELDS[index];
        DWORD value = 0u;
        if (!field->writable &&
            (copy_readable(
                 (const void *)(ULONG_PTR)(flight_address + field->offset),
                 (BYTE *)&value, field->width) != field->width ||
             (field->width == 1u
                  ? (value & 0xffu) != (replay_runtime_state[index] & 0xffu)
                  : value != replay_runtime_state[index]))) {
            return FALSE;
        }
    }
    for (index = 0u; index < RUNTIME_STATE_FIELD_COUNT; ++index) {
        const RuntimeStateField *field = &RUNTIME_STATE_FIELDS[index];
        if (field->writable && !copy_writable(
                (void *)(ULONG_PTR)(flight_address + field->offset),
                &replay_runtime_state[index], field->width)) {
            return FALSE;
        }
    }
    MemoryBarrier();
    for (index = 0u; index < RUNTIME_STATE_FIELD_COUNT; ++index) {
        const RuntimeStateField *field = &RUNTIME_STATE_FIELDS[index];
        DWORD value = 0u;
        if (copy_readable(
                (const void *)(ULONG_PTR)(flight_address + field->offset),
                (BYTE *)&value, field->width) != field->width ||
            (field->width == 1u
                 ? (value & 0xffu) != (replay_runtime_state[index] & 0xffu)
                 : value != replay_runtime_state[index])) {
            return FALSE;
        }
        emit_runtime_state_field("readback", index, value);
    }
    emit_runtime_state_complete("readback");
    return TRUE;
}

static BOOL read_byte(DWORD address, DWORD offset, BYTE *value)
{
    return copy_readable((const void *)(ULONG_PTR)(address + offset),
                         value, sizeof(*value)) == sizeof(*value);
}

static BOOL copy_mode_name(const char *source, char output[MODE_NAME_SIZE])
{
    DWORD index;
    if (!source) goto invalid;
    for (index = 0u; index + 1u < MODE_NAME_SIZE; ++index) {
        BYTE value = 0u;
        if (copy_readable(source + index, &value, sizeof(value)) !=
            sizeof(value)) goto invalid;
        if (value == '\0') {
            if (index == 0u) goto invalid;
            output[index] = '\0';
            return TRUE;
        }
        if (!((value >= 'a' && value <= 'z') ||
              (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') || value == '_' ||
              value == '-')) goto invalid;
        output[index] = (char)value;
    }
invalid:
    memcpy(output, "invalid", sizeof("invalid"));
    return FALSE;
}

static const char *mode_name_for_object(DWORD object)
{
    DWORD vtable = 0u;
    DWORD index;
    if (object == 0u || !read_pointer(object, 0u, &vtable)) return NULL;
    for (index = 0u; index < BODY_MODE_COUNT; ++index) {
        if (BODY_MODE_LIFECYCLES[index].vtable == vtable) {
            return BODY_MODE_LIFECYCLES[index].mode_name;
        }
    }
    return NULL;
}

static const char *current_manager_mode_name(void)
{
    DWORD application = (DWORD)(ULONG_PTR)(
        (ApplicationGetterFunction)(ULONG_PTR)APPLICATION_GETTER)();
    DWORD manager = 0u, current = 0u;
    if (application == 0u ||
        !read_pointer(application, 0x1acu, &manager) || manager == 0u ||
        !read_pointer(manager, 0x18cu, &current)) return NULL;
    return mode_name_for_object(current);
}

static void emit_natural_session(const char *phase, const char *result)
{
    char line[512];
    volatile LONG *gate;
    int size;
    if (!natural_capture_edge || !trace_lock_ready) return;
    if (strcmp(phase, "complete") == 0 &&
        InterlockedCompareExchange(&natural_session_started, 0, 0) != 1) {
        return;
    }
    gate = strcmp(phase, "start") == 0 ?
        &natural_session_started : &natural_session_completed;
    if (InterlockedCompareExchange(gate, 1, 0) != 0) return;
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":3,"
        "\"protocol\":\"miel-vliegt-native-natural-transition\","
        "\"record\":\"natural_session_%s\","
        "\"scenario\":\"%s\","
        "\"executable_sha256\":\"%s\","
        "\"hook_build\":\"%s\","
        "\"observer_dll_sha256\":\"%s\",\"result\":\"%s\","
        "\"thread_id\":%lu}\r\n",
        phase, replay_scenario, NATURAL_EXECUTABLE_SHA256,
        NATURAL_HOOK_BUILD, natural_observer_sha256, result,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) {
        append_record(line, (DWORD)size);
    }
}

static void emit_natural_transition(
    const NaturalTransitionEdge *edge, DWORD observed_site)
{
    char line[768];
    DWORD sequence;
    int size;
    if (!edge || edge != natural_capture_edge ||
        InterlockedCompareExchange(&natural_session_started, 0, 0) != 1 ||
        InterlockedCompareExchange(&natural_session_completed, 0, 0) != 0 ||
        session_state == SESSION_FAILED || session_state == SESSION_COMPLETE ||
        InterlockedCompareExchange(&natural_transition_emitted, 1, 0) != 0) {
        return;
    }
    sequence = next_id(&natural_sequence_number);
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":3,"
        "\"protocol\":\"miel-vliegt-native-natural-transition\","
        "\"record\":\"scene_transition_source\","
        "\"edge\":\"%s\",\"transition_site\":\"0x%08lx\","
        "\"sequence\":%lu,\"tick\":%lu,\"thread_id\":%lu,"
        "\"scenario\":\"%s\","
        "\"executable_sha256\":\"%s\","
        "\"hook_build\":\"%s\","
        "\"observer_dll_sha256\":\"%s\"}\r\n",
        edge->id, (unsigned long)observed_site, (unsigned long)sequence,
        (unsigned long)InterlockedCompareExchange(&manager_tick_count, 0, 0),
        (unsigned long)GetCurrentThreadId(), replay_scenario,
        NATURAL_EXECUTABLE_SHA256, NATURAL_HOOK_BUILD,
        natural_observer_sha256);
    if (size > 0 && (size_t)size < sizeof(line)) {
        append_record(line, (DWORD)size);
        InterlockedExchange(&post_natural_edge_input_suspended, 1);
    }
}

static NaturalCallbackThread *natural_callback_thread(BOOL create)
{
    DWORD index;
    LONG thread_id = (LONG)GetCurrentThreadId();
    for (index = 0u; index < NATURAL_THREAD_CONTEXT_COUNT; ++index) {
        if (natural_callback_threads[index].owner_thread_id == thread_id) {
            return &natural_callback_threads[index];
        }
    }
    if (!create) return NULL;
    for (index = 0u; index < NATURAL_THREAD_CONTEXT_COUNT; ++index) {
        NaturalCallbackThread *context = &natural_callback_threads[index];
        if (InterlockedCompareExchange(
                &context->owner_thread_id, thread_id, 0) == 0) {
            context->depth = 0u;
            return context;
        }
    }
    return NULL;
}

static DWORD natural_exhibition_index(void)
{
    NaturalCallbackThread *context = natural_callback_thread(FALSE);
    return !context || context->depth == 0u ? INVALID_ID :
        context->frames[context->depth - 1u].index;
}

static DWORD __attribute__((used)) natural_exhibition_enter(
    DWORD index, DWORD original_return)
{
    NaturalCallbackThread *context;
    NaturalCallbackFrame *frame;
    BOOL relevant = natural_capture_edge &&
        ((strcmp(natural_capture_edge->id,
                 "varldsutstallning.barn.callback") == 0 && index == 2u) ||
         (strcmp(natural_capture_edge->id,
                 "varldsutstallning.credits") == 0 && index == 3u));
    if (!relevant) return original_return;
    context = natural_callback_thread(TRUE);
    if (!context || context->depth >= NATURAL_CALLBACK_DEPTH) {
        session_fail("natural_exhibition_context_contract");
        return original_return;
    }
    frame = &context->frames[context->depth++];
    frame->index = index;
    frame->original_return = original_return;
    return (DWORD)(ULONG_PTR)exhibition_callback_leave_hook;
}

static DWORD __attribute__((used)) natural_exhibition_leave(void)
{
    NaturalCallbackThread *context = natural_callback_thread(FALSE);
    DWORD original_return;
    if (!context || context->depth == 0u) {
        session_fail("natural_exhibition_pair_contract");
        return 0u;
    }
    original_return = context->frames[--context->depth].original_return;
    return original_return;
}

static BOOL natural_source_matches(
    const NaturalTransitionEdge *edge, const char *source_mode)
{
    return edge->source_mode[0] == '\0' ||
        (source_mode && strcmp(edge->source_mode, source_mode) == 0);
}

static void observe_natural_mode_set(
    const ModeTransitionObservation *transition)
{
    const NaturalTransitionEdge *edge = natural_capture_edge;
    DWORD callback_index;
    DWORD site;
    if (!edge ||
        (edge->kind != NATURAL_MODE_SET &&
         edge->kind != NATURAL_LOCATION_DEPARTURE) ||
        !transition->requested_mode_valid || transition->expected_mode == 0u ||
        strcmp(edge->target_mode, transition->requested_mode) != 0 ||
        !natural_source_matches(
            edge, transition->source_mode_valid ? transition->source_mode : NULL)) {
        return;
    }
    site = transition->caller_site;
    if (edge->kind == NATURAL_LOCATION_DEPARTURE) {
        if (site != 0x00425c2eu && site != 0x00425cb1u &&
            site != 0x00425e90u && site != 0x00425fe5u &&
            site != 0x004262eeu) return;
        emit_natural_transition(edge, site);
        return;
    }
    if (strcmp(edge->id, "mission.mecchifinal.outro") == 0) {
        if (site == 0x0041e246u || site == 0x0043676du) {
            emit_natural_transition(edge, site);
        }
        return;
    }
    callback_index = natural_exhibition_index();
    if (strcmp(edge->id, "varldsutstallning.credits") == 0) {
        if (site == 0x0041eadau && callback_index == 3u) {
            emit_natural_transition(edge, edge->site);
        }
        return;
    }
    if (strcmp(edge->id, "varldsutstallning.barn.callback") == 0) {
        if (site == edge->site && callback_index == 2u) {
            emit_natural_transition(edge, edge->site);
        }
        return;
    }
    if (strcmp(edge->id, "varldsutstallning.barn.state5") == 0) {
        if (site == edge->site && callback_index == INVALID_ID) {
            emit_natural_transition(edge, edge->site);
        }
        return;
    }
    if (site == edge->site) emit_natural_transition(edge, edge->site);
}

static void __attribute__((used)) observe_flight_target(
    const char *target_mode, DWORD caller_return)
{
    char target[MODE_NAME_SIZE];
    const char *source;
    BOOL target_valid;
    DWORD site = caller_return >= 5u ? caller_return - 5u : 0u;
    char line[512];
    DWORD sequence;
    int size;

    target_valid = copy_mode_name(target_mode, target);
    source = current_manager_mode_name();
    sequence = next_id(&flight_target_sequence_number);
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-flight-target\","
        "\"sequence\":%lu,\"target_mode\":\"%s\","
        "\"target_mode_valid\":%s,\"source_mode\":\"%s\","
        "\"source_mode_valid\":%s,\"caller_site\":\"0x%08lx\","
        "\"tick\":%lu,\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, target_valid ? target : "",
        target_valid ? "true" : "false", source ? source : "",
        source ? "true" : "false", (unsigned long)site,
        (unsigned long)InterlockedCompareExchange(&manager_tick_count, 0, 0),
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) {
        append_record(line, (DWORD)size);
    }

    const NaturalTransitionEdge *edge = natural_capture_edge;
    if (!edge || edge->kind != NATURAL_FLIGHT_TARGET ||
        (site != 0x00430fa4u && site != 0x0042d756u) ||
        !target_valid ||
        strcmp(edge->target_mode, target) != 0) return;
    if (!natural_source_matches(edge, source) || site != edge->site) return;
    emit_natural_transition(edge, site);
}

static void __attribute__((used)) observe_queue_mode(
    DWORD manager, DWORD queued_mode, DWORD caller_return)
{
    const NaturalTransitionEdge *edge = natural_capture_edge;
    DWORD current = 0u;
    const char *source;
    DWORD site = caller_return >= 5u ? caller_return - 5u : 0u;
    if (!edge || edge->kind != NATURAL_QUEUE_MODE || site != edge->site ||
        queued_mode != 0u || !read_pointer(manager, 0x18cu, &current)) return;
    source = mode_name_for_object(current);
    if (natural_source_matches(edge, source)) {
        emit_natural_transition(edge, site);
    }
}

static void emit_mode_transition(const char *phase,
                                 const ModeTransitionObservation *transition,
                                 DWORD return_value,
                                 BOOL immediate_activation,
                                 BOOL pending_observed)
{
    char line[640];
    DWORD sequence = next_id(&mode_transition_sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-mode-transition\","
        "\"sequence\":%lu,\"phase\":\"%s\","
        "\"transition_id\":%lu,\"requested_mode\":\"%s\","
        "\"requested_mode_valid\":%s,\"return_byte\":%lu,"
        "\"caller_site\":\"0x%08lx\","
        "\"source_mode\":\"%s\",\"source_mode_valid\":%s,"
        "\"immediate_activation\":%s,\"pending_observed\":%s,"
        "\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, phase,
        (unsigned long)transition->id, transition->requested_mode,
        transition->requested_mode_valid ? "true" : "false",
        (unsigned long)(return_value & 0xffu),
        (unsigned long)transition->caller_site,
        transition->source_mode_valid ? transition->source_mode : "",
        transition->source_mode_valid ? "true" : "false",
        immediate_activation ? "true" : "false",
        pending_observed ? "true" : "false",
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_mode_activation(ModeTransitionObservation *transition,
                                 const char *correlation)
{
    char line[512];
    DWORD sequence;
    int size;
    if (InterlockedCompareExchange(&transition->state, 3, 2) != 2) return;
    sequence = next_id(&mode_transition_sequence_number);
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-mode-transition\","
        "\"sequence\":%lu,\"phase\":\"activate\","
        "\"transition_id\":%lu,\"requested_mode\":\"%s\","
        "\"requested_mode_valid\":%s,"
        "\"correlation\":\"%s\",\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, (unsigned long)transition->id,
        transition->requested_mode,
        transition->requested_mode_valid ? "true" : "false", correlation,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
    if (session_state == SESSION_DISPATCHED &&
        transition->id == 2u && transition->requested_mode_valid &&
        strcmp(transition->requested_mode, "mode_mygghanget") == 0) {
        if (native_capture_driver_needs_flight_bootstrap()) {
            if (!transition->source_mode_valid ||
                strcmp(transition->source_mode, "mode_barn") != 0 ||
                strcmp(correlation, "manager_tick_current_mode") != 0 ||
                flight_activation_clock_open ||
                flight_activation_rng_open || flight_activation_seed_applied) {
                session_fail(
                    "native_capture_driver_flight_clock_boundary_contract");
            }
        } else if (!transition->source_mode_valid ||
            strcmp(transition->source_mode, "mode_barn") != 0 ||
            strcmp(correlation, "manager_tick_current_mode") != 0 ||
            !location_phase_rng_seeded ||
            !location_phase_rng_complete ||
            location_phase_rng_count != LOCATION_PHASE_RAND_COUNT ||
            flight_activation_clock_open || flight_activation_seed_applied ||
            replay_ticks == NULL) {
            session_fail("flight_activation_clock_boundary_contract");
        } else {
            flight_activation_clock_count = 0u;
            replay_activation_dt_next = 0u;
            sha256_init(&flight_activation_clock_sha256);
            flight_activation_clock_open = TRUE;
        }
    }
}

static BOOL record_bootstrap_pending_login(DWORD manager)
{
    DWORD current = 0u, pending = 0u;
    DWORD id;
    void *login;
    ModeTransitionObservation *transition;
    if (manager == 0u ||
        !read_pointer(manager, 0x18cu, &current) || current != 0u ||
        !read_pointer(manager, 0x190u, &pending) || pending == 0u) {
        return FALSE;
    }
    login = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
        (void *)(ULONG_PTR)manager, "mode_login");
    if (login == NULL || pending != (DWORD)(ULONG_PTR)login) return FALSE;
    id = next_id(&mode_transition_number);
    if (id != 0u) return FALSE;
    transition = &mode_transitions[0];
    InterlockedExchange(&transition->state, 0);
    transition->id = 0u;
    transition->manager_address = manager;
    transition->previous_mode = 0u;
    transition->expected_mode = pending;
    transition->caller_site = 0x0041d763u;
    transition->source_mode[0] = '\0';
    transition->source_mode_valid = FALSE;
    memcpy(transition->requested_mode, "mode_login", sizeof("mode_login"));
    transition->requested_mode_valid = TRUE;
    MemoryBarrier();
    InterlockedExchange(&transition->state, 2);
    emit_mode_transition("bootstrap_pending", transition, 0u, FALSE, TRUE);
    return InterlockedCompareExchange(&observer_ready, 0, 0) == 1 &&
        login_pending_event && SetEvent(login_pending_event);
}

static void __attribute__((used)) record_mode_transition_entry(
    DWORD manager_address, const char *requested_mode, DWORD *transition_id,
    DWORD caller_return)
{
    DWORD last_error = GetLastError();
    if (calibration_observation_only &&
        InterlockedCompareExchange(&observer_ready, 0, 0) != 1) {
        LONG observed_manager = InterlockedCompareExchange(
            &late_bootstrap_manager_address, (LONG)manager_address, 0);
        if ((observed_manager != 0 &&
             observed_manager != (LONG)manager_address) ||
            !late_bootstrap_event || !SetEvent(late_bootstrap_event)) {
            session_fail("late_bootstrap_mode_set_contract");
        }
    }
    if (InterlockedCompareExchange(&body_callback_active, 0, 0) != 0) {
        /* BODY_ONLY dispatch has its own receipt contract.  It must never
         * enter the natural-transition diagnostic sequence. */
        *transition_id = INVALID_ID;
        SetLastError(last_error);
        return;
    }
    DWORD id = next_id(&mode_transition_number);
    ModeTransitionObservation *transition =
        &mode_transitions[id % MODE_TRANSITION_LIMIT];
    InterlockedExchange(&transition->state, 0);
    transition->id = id;
    transition->manager_address = manager_address;
    transition->previous_mode = 0u;
    transition->expected_mode = 0u;
    transition->caller_site = caller_return >= 5u ? caller_return - 5u : 0u;
    transition->source_mode[0] = '\0';
    transition->source_mode_valid = FALSE;
    transition->requested_mode_valid = copy_mode_name(
        requested_mode, transition->requested_mode);
    read_pointer(manager_address, 0x18cu, &transition->previous_mode);
    {
        const char *source = mode_name_for_object(transition->previous_mode);
        if (source) {
            strncpy(transition->source_mode, source, MODE_NAME_SIZE - 1u);
            transition->source_mode[MODE_NAME_SIZE - 1u] = '\0';
            transition->source_mode_valid = TRUE;
        }
    }
    MemoryBarrier();
    InterlockedExchange(&transition->state, 1);
    *transition_id = id;
    emit_mode_transition("entry", transition, 0u, FALSE, FALSE);
    if (id == 0u) {
        if (transition->caller_site != 0x0041d763u ||
            !transition->requested_mode_valid ||
            strcmp(transition->requested_mode, "mode_login") != 0 ||
            transition->previous_mode != 0u) {
            session_fail("bootstrap_login_ready_happens_before_contract");
        } else if (!calibration_observation_only &&
                   (WaitForSingleObject(
                        ready_event, OBSERVER_READY_WAIT_MS) != WAIT_OBJECT_0 ||
                    InterlockedCompareExchange(
                        &observer_ready, 0, 0) != 1)) {
            session_fail("bootstrap_login_ready_happens_before_contract");
        }
    }
    if (id == 1u) {
        if (InterlockedCompareExchange(
                &login_activation_observed, 0, 0) != 1) {
            session_fail("mode_set_before_login_activation");
        } else if (transition->manager_address !=
                   mode_transitions[0].manager_address) {
            session_fail("first_called_mode_transition_manager_mismatch");
        } else if (!transition->requested_mode_valid ||
                   strcmp(transition->requested_mode, "mode_barn") != 0) {
            session_fail("first_called_mode_transition_not_barn");
        }
    }
    if (session_state == SESSION_DISPATCHED &&
        transition->requested_mode_valid &&
        strcmp(transition->requested_mode, "mode_fly") == 0) {
        if (native_capture_driver_needs_flight_bootstrap()) {
            if (!transition->source_mode_valid ||
                strcmp(transition->source_mode, "mode_mygghanget") != 0 ||
                (transition->caller_site != 0x00425c2eu &&
                 transition->caller_site != 0x004262eeu) ||
                flight_activation_seed_applied || flight_activation_rng_open ||
                flight_activation_clock_open) {
                session_fail(
                    "native_capture_driver_flight_seed_boundary_contract");
            }
        } else if (body_position_probe_enabled &&
            transition->source_mode_valid &&
            strcmp(transition->source_mode, body_mode_name) == 0 &&
            transition->caller_site == 0x00425c2eu) {
            /* A directly dispatched location inherits the shared airplane
             * transform.  State zero may immediately take its original
             * offscreen departure branch.  That is not a Mygghanget flight
             * activation and cannot seed or prove a BODY scene route. */
            session_fail("body_position_probe_requires_natural_landing_contract");
        } else if (flight_activation_seed_applied ||
            !transition->source_mode_valid ||
            strcmp(transition->source_mode, "mode_mygghanget") != 0 ||
            !flight_activation_clock_open ||
            (transition->caller_site != 0x00425c2eu &&
             transition->caller_site != 0x004262eeu)) {
            session_fail("flight_activation_seed_boundary_contract");
        } else {
            original_srand((unsigned int)replay_flight_activation_seed);
            flight_activation_seed_applied = TRUE;
            flight_activation_rng_count = 0u;
            sha256_init(&flight_activation_rng_sha256);
            flight_activation_rng_open = TRUE;
            InterlockedExchange(&particle_activation_epoch_open, 1);
            rng_seed_count = 1u;
            emit_rng("seed", 0u, replay_flight_activation_seed, NULL);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) record_mode_transition_leave(
    DWORD manager_address, const char *requested_mode, DWORD transition_id,
    DWORD return_value)
{
    DWORD last_error = GetLastError();
    DWORD current = 0u, pending = 0u;
    ModeTransitionObservation *transition =
        &mode_transitions[transition_id % MODE_TRANSITION_LIMIT];
    BOOL current_read = read_pointer(manager_address, 0x18cu, &current);
    BOOL pending_read = read_pointer(manager_address, 0x190u, &pending);
    BOOL immediate;
    (void)requested_mode;
    if (transition_id == INVALID_ID) goto done;
    if (transition->id != transition_id || transition->manager_address !=
        manager_address || transition->state != 1) goto done;
    immediate = current_read && current != 0u &&
        current != transition->previous_mode;
    transition->expected_mode = immediate ? current :
        (pending_read ? pending : 0u);
    InterlockedExchange(&transition->state, 2);
    emit_mode_transition("leave", transition, return_value, immediate,
                         pending_read && pending != 0u);
    if (calibration_observation_only &&
        transition_id != 0u &&
        !ensure_calibration_manager_tick_interposition()) {
        session_fail("calibration_manager_tick_slot_contract");
    }
    if (transition_id == 0u) {
        if (calibration_observation_only &&
            (!complete_observer_bootstrap(manager_address) ||
             !ensure_calibration_manager_tick_interposition())) {
            session_fail("late_bootstrap_mode_set_leave_contract");
        }
        if ((return_value & 0xffu) == 0u ||
            transition->caller_site != 0x0041d763u ||
            !transition->requested_mode_valid ||
            strcmp(transition->requested_mode, "mode_login") != 0 ||
            transition->previous_mode != 0u || !current_read || current != 0u ||
            !pending_read || pending == 0u ||
            transition->expected_mode != pending || immediate ||
            InterlockedCompareExchange(&observer_ready, 0, 0) != 1 ||
            !login_pending_event || !SetEvent(login_pending_event)) {
            session_fail("bootstrap_login_pending_mode_set_contract");
        }
    }
    if ((return_value & 0xffu) != 0u) observe_natural_mode_set(transition);
    if (immediate) emit_mode_activation(transition, "mode_set_leave");
done:
    SetLastError(last_error);
}

static void correlate_mode_activation(DWORD manager_address)
{
    DWORD current = 0u, pending = 0u, index;
    ModeTransitionObservation *bootstrap = &mode_transitions[0];
    if (!read_pointer(manager_address, 0x18cu, &current) ||
        !read_pointer(manager_address, 0x190u, &pending)) {
        if (bootstrap->state == 2 && bootstrap->id == 0u &&
            bootstrap->manager_address == manager_address) {
            session_fail("bootstrap_login_activation_read_contract");
        }
        return;
    }
    if (bootstrap->state == 2 && bootstrap->id == 0u &&
        bootstrap->manager_address == manager_address) {
        if (current == bootstrap->expected_mode && pending == 0u) {
            emit_mode_activation(bootstrap, "manager_tick_current_mode");
            if (bootstrap->state == 3) {
                InterlockedExchange(&login_activation_observed, 1);
                if (!login_activation_event ||
                    !SetEvent(login_activation_event)) {
                    session_fail("login_activation_event_contract");
                }
            }
        } else if (current != 0u || pending != bootstrap->expected_mode) {
            session_fail("bootstrap_login_activation_contract");
        }
        return;
    }
    if (current == 0u) return;
    for (index = 0u; index < MODE_TRANSITION_LIMIT; ++index) {
        ModeTransitionObservation *transition = &mode_transitions[index];
        if (transition->state == 2 &&
            transition->manager_address == manager_address &&
            transition->expected_mode == current) {
            emit_mode_activation(transition, "manager_tick_current_mode");
        }
    }
}

static void emit_observation_profile(void)
{
    char line[1536];
    DWORD sequence = next_id(&diagnostic_sequence_number);
    BOOL target_scoped = native_dispatch_requested &&
        native_dispatch_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2;
    const char *profile = calibration_observation_only ? "calibration-only" :
        scenario_bounded_observation ? MVOP_SEMANTIC_OBSERVER_PROFILE :
        semantic_observation_only ? "semantic-only" :
        target_scoped ? "native-dispatch-target-scoped" :
        MVOP_VISUAL_OBSERVER_PROFILE;
    const char *profile_id = scenario_bounded_observation ?
        MVOP_SEMANTIC_ID :
        (!semantic_observation_only && !target_scoped ?
            MVOP_VISUAL_ID : "");
    const char *profile_sha256 = scenario_bounded_observation ?
        MVOP_SEMANTIC_PROFILE_SHA256 :
        (!semantic_observation_only && !target_scoped ?
            MVOP_VISUAL_PROFILE_SHA256 : "");
    const char *applicable_receipt_channels =
        scenario_bounded_observation ?
            MVOP_SEMANTIC_APPLICABLE_RECEIPT_CHANNELS_JSON :
        (!semantic_observation_only && !target_scoped ?
            MVOP_VISUAL_APPLICABLE_RECEIPT_CHANNELS_JSON : "[]");
    const char *omitted_receipt_channels =
        scenario_bounded_observation ?
            MVOP_SEMANTIC_OMITTED_RECEIPT_CHANNELS_JSON :
        (!semantic_observation_only && !target_scoped ?
            MVOP_VISUAL_OMITTED_RECEIPT_CHANNELS_JSON : "[]");
    const char *omitted = calibration_observation_only ?
        "[\"controls-values\",\"physics\",\"collision\",\"camera-values\","
        "\"render-values\",\"fuel\",\"contact\",\"damage\",\"terrain\","
        "\"udsp\",\"position-character\",\"particle-lifecycle\","
        "\"presentation-render\",\"shadow-render\"]" :
        scenario_bounded_observation ?
        MVOP_SEMANTIC_OBSERVER_OMITTED_CHANNELS_JSON :
        semantic_observation_only &&
        (semantic_observation_omit_mask &
         OBSERVE_OMIT_AIRPLANE_SHADOW_FAMILY) ==
            OBSERVE_OMIT_AIRPLANE_SHADOW_FAMILY ?
        "[\"particle-lifecycle\",\"presentation-render\",\"shadow-render\"]" :
        semantic_observation_only ?
        "[\"particle-lifecycle\",\"presentation-render\"]" :
        target_scoped ? "[\"non-target-observer-hooks\"]" : "[]";
    const char *eligible =
        (calibration_observation_only ||
         (semantic_observation_only && !scenario_bounded_observation))
            ? "false" : "true";
    const char *blocker = calibration_observation_only
        ? "\"calibration_only\"" :
        semantic_observation_only && !scenario_bounded_observation
            ? "\"startup_scheduler_divergence\"" : "null";
    const char *retained = calibration_observation_only ?
        "[\"session\",\"input-proof\",\"clock.tick\",\"flight.tick\","
        "\"rng\",\"runtime-initial-state\",\"flight-activation-rng\","
        "\"flight-activation-clock\",\"render.framebuffer\"]" : "[]";
    int size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-observation-profile\","
        "\"sequence\":%lu,\"profile\":\"%s\","
        "\"profile_id\":\"%s\",\"profile_sha256\":\"%s\","
        "\"contract_sha256\":\"%s\","
        "\"omit_mask\":\"0x%04lx\","
        "\"target_hook_mask\":\"0x%08lx\","
        "\"omitted_channels\":%s,"
        "\"retained_channels\":%s,"
        "\"applicable_receipt_channels\":%s,"
        "\"omitted_receipt_channels\":%s,"
        "\"framebuffer_required\":%s,"
        "\"evidence_eligible\":%s,\"evidence_blocker\":%s,"
        "\"signature_preflight_complete\":true,"
        "\"profile_state_writes\":false,\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, profile, profile_id, profile_sha256,
        MVOP_CONTRACT_SHA256,
        (unsigned long)semantic_observation_omit_mask,
        (unsigned long)(target_scoped ? mvds_required_hook_mask() : 0u),
        omitted, retained, applicable_receipt_channels,
        omitted_receipt_channels,
        !semantic_observation_only && !target_scoped &&
            MVOP_VISUAL_FRAMEBUFFER_REQUIRED ? "true" : "false",
        eligible, blocker,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) {
        append_record(line, (DWORD)size);
    }
}

static void emit_bootstrap_diagnostic(void)
{
    DWORD application = (DWORD)(ULONG_PTR)(
        (ApplicationGetterFunction)(ULONG_PTR)APPLICATION_GETTER)();
    DWORD dispatcher = 0u, audio = 0u, controls = 0u;
    DWORD archive = 0u, video = 0u, presentation = 0u;
    DWORD manager = 0u, manager_application = 0u;
    DWORD current = 0u, pending = 0u, physics = 0u;
    DWORD mode = 0u, mode_count = 0u, next_mode = 0u;
    DWORD login_manager = 0u, login_application = 0u;
    DWORD barn_airplane = 0u, barn_view = INVALID_ID;
    DWORD current_manager = 0u, current_camera = 0u, current_physics = 0u;
    DWORD current_flight_component = 0u, shared_flight_component = 0u;
    DWORD location_state = INVALID_ID;
    DWORD start_engine_throttle_bits = INVALID_ID;
    DWORD start_engine_timer_bits = INVALID_ID;
    DWORD start_engine_audio_owner = INVALID_ID;
    DWORD start_engine_audio_take = INVALID_ID;
    DWORD start_engine_global_phase = INVALID_ID;
    BYTE native_preroll_state = 0xffu;
    BYTE start_engine_latched = 0xffu;
    BYTE start_engine_faster_sample = 0xffu;
    void *login = NULL, *flight = NULL, *barn = NULL, *mygghanget = NULL;
    const char *current_name = "unresolved";
    size_t mode_name_index;
    int user_id = -999, airplane_complete = -1;
    BYTE loaded = 0u, opened = 0u, flight_loaded = 0u, flight_opened = 0u;
    BYTE mygghanget_flight_start = 0u;
    char line[1536];
    int size;
    if (application != 0u) {
        read_pointer(application, 0x190u, &controls);
        read_pointer(application, 0x194u, &dispatcher);
        read_pointer(application, 0x198u, &audio);
        read_pointer(application, 0x19cu, &archive);
        read_pointer(application, 0x1a0u, &video);
        read_pointer(application, 0x1a4u, &presentation);
        read_pointer(application, 0x1acu, &manager);
    }
    if (manager != 0u) {
        read_pointer(manager, 0x10cu, &manager_application);
        read_pointer(manager, 0x154u, &physics);
        read_pointer(manager, 0x18cu, &current);
        read_pointer(manager, 0x190u, &pending);
        read_byte(manager + 0x108u, 0x74u, &start_engine_faster_sample);
    }
    if (physics != 0u) {
        read_byte(physics, 0x124u, &native_preroll_state);
    }
    copy_readable((const void *)(ULONG_PTR)0x0045f2fcu,
                  (BYTE *)&mode, sizeof(mode));
    while (mode != 0u && mode_count < 128u &&
           read_pointer(mode, 0x30u, &next_mode)) {
        ++mode_count;
        mode = next_mode;
    }
    if (current != 0u) {
        read_byte(current, 0x14u, &loaded);
        read_byte(current, 0x15u, &opened);
    }
    if (manager != 0u) {
        login = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
            (void *)(ULONG_PTR)manager, "mode_login");
        flight = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
            (void *)(ULONG_PTR)manager, "mode_fly");
        barn = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
            (void *)(ULONG_PTR)manager, "mode_barn");
        mygghanget = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
            (void *)(ULONG_PTR)manager, "mode_mygghanget");
        for (mode_name_index = 0u;
             current != 0u &&
             mode_name_index < BODY_MODE_COUNT;
             ++mode_name_index) {
            void *candidate = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
                (void *)(ULONG_PTR)manager,
                BODY_MODE_ALLOWLIST[mode_name_index]);
            if (current == (DWORD)(ULONG_PTR)candidate) {
                current_name = BODY_MODE_ALLOWLIST[mode_name_index];
                break;
            }
        }
        user_id = ((UserGetIdFunction)(ULONG_PTR)USER_GET_ID)(
            (void *)(ULONG_PTR)application);
    }
    if (flight != NULL) {
        DWORD flight_address = (DWORD)(ULONG_PTR)flight;
        read_byte(flight_address, 0x14u, &flight_loaded);
        read_byte(flight_address, 0x15u, &flight_opened);
        read_pointer(flight_address, 0xc0u, &shared_flight_component);
    }
    if (current != 0u && current == (DWORD)(ULONG_PTR)mygghanget) {
        read_byte(current, 0x999u, &mygghanget_flight_start);
        read_pointer(current, 0x50u, &current_manager);
        read_pointer(current, 0x54u, &current_camera);
        read_pointer(current, 0x5cu, &current_physics);
        read_pointer(current, 0x60u, &current_flight_component);
        copy_readable((const void *)(ULONG_PTR)(current + 0x8dcu),
                      (BYTE *)&location_state, sizeof(location_state));
        read_byte(current, 0x8b4u, &start_engine_latched);
        copy_readable((const void *)(ULONG_PTR)(current + 0x8b8u),
                      (BYTE *)&start_engine_timer_bits,
                      sizeof(start_engine_timer_bits));
        copy_readable((const void *)(ULONG_PTR)(current + 0x8bcu),
                      (BYTE *)&start_engine_audio_owner,
                      sizeof(start_engine_audio_owner));
        copy_readable((const void *)(ULONG_PTR)(current + 0x8c0u),
                      (BYTE *)&start_engine_audio_take,
                      sizeof(start_engine_audio_take));
        if (current_physics != 0u) {
            copy_readable(
                (const void *)(ULONG_PTR)(current_physics + 0x148u),
                (BYTE *)&start_engine_throttle_bits,
                sizeof(start_engine_throttle_bits));
        }
        copy_readable((const void *)(ULONG_PTR)0x0045a814u,
                      (BYTE *)&start_engine_global_phase,
                      sizeof(start_engine_global_phase));
    }
    if (current != 0u && current == (DWORD)(ULONG_PTR)barn &&
        read_pointer(current, 0x160u, &barn_airplane) &&
        copy_readable((const void *)(ULONG_PTR)(current + 0x190u),
                      (BYTE *)&barn_view, sizeof(barn_view)) ==
            sizeof(barn_view) && barn_airplane != 0u) {
        airplane_complete = (int)(
            (AirplaneCompleteFunction)(ULONG_PTR)AIRPLANE_COMPLETE)(
                (void *)(ULONG_PTR)barn_airplane);
    }
    if (current != 0u && current == (DWORD)(ULONG_PTR)login) {
        read_pointer(current, 0x48u, &login_manager);
        read_pointer(current, 0x4u, &login_application);
    }
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,\"protocol\":\"miel-vliegt-native-bootstrap\","
        "\"application\":%s,\"controls\":%s,\"dispatcher\":%s,"
        "\"audio\":%s,\"archive\":%s,\"video\":%s,"
        "\"presentation\":%s,\"manager\":%s,\"manager_alias\":%s,"
        "\"current_mode\":%s,\"current_is_login\":%s,"
        "\"current_is_flight\":%s,\"current_name\":\"%s\","
        "\"current_is_mygghanget\":%s,\"mygghanget_flight_start\":%u,"
        "\"location_state\":%lu,\"location_manager_alias\":%s,"
        "\"start_engine_faster_sample\":%u,"
        "\"start_engine_throttle_f32_bits\":\"0x%08lx\","
        "\"start_engine_timer_f32_bits\":\"0x%08lx\","
        "\"start_engine_latched\":%u,"
        "\"start_engine_audio_owner\":%lu,"
        "\"start_engine_audio_take\":%lu,"
        "\"start_engine_global_phase\":%lu,"
        "\"location_camera\":%s,\"location_physics_alias\":%s,"
        "\"location_shared_flight_alias\":%s,\"flight_loaded\":%u,"
        "\"flight_opened\":%u,"
        "\"login_aliases\":%s,"
        "\"user_id\":%d,\"pending_mode\":%s,"
        "\"native_preroll_state\":%lu,\"native_preroll_pending\":%s,"
        "\"barn_view\":%lu,\"airplane_complete\":%d,"
        "\"mode_count\":%lu,\"current_loaded\":%u,"
        "\"current_opened\":%u,\"manager_ticks\":%ld}\r\n",
        application != 0u ? "true" : "false",
        controls != 0u ? "true" : "false",
        dispatcher != 0u ? "true" : "false",
        audio != 0u ? "true" : "false",
        archive != 0u ? "true" : "false",
        video != 0u ? "true" : "false",
        presentation != 0u ? "true" : "false",
        manager != 0u ? "true" : "false",
        manager_application == application && application != 0u ? "true" : "false",
        current != 0u ? "true" : "false",
        current != 0u && current == (DWORD)(ULONG_PTR)login ? "true" : "false",
        current != 0u && current == (DWORD)(ULONG_PTR)flight ? "true" : "false",
        current_name,
        current != 0u && current == (DWORD)(ULONG_PTR)mygghanget ?
            "true" : "false",
        (unsigned int)mygghanget_flight_start,
        (unsigned long)location_state,
        current_manager == manager && manager != 0u ? "true" : "false",
        (unsigned int)start_engine_faster_sample,
        (unsigned long)start_engine_throttle_bits,
        (unsigned long)start_engine_timer_bits,
        (unsigned int)start_engine_latched,
        (unsigned long)start_engine_audio_owner,
        (unsigned long)start_engine_audio_take,
        (unsigned long)start_engine_global_phase,
        current_camera != 0u ? "true" : "false",
        current_physics == physics && physics != 0u ? "true" : "false",
        current_flight_component == shared_flight_component &&
            shared_flight_component != 0u ? "true" : "false",
        (unsigned int)flight_loaded, (unsigned int)flight_opened,
        login_manager == manager && login_application == application &&
            manager != 0u ? "true" : "false",
        user_id,
        pending != 0u ? "true" : "false",
        (unsigned long)native_preroll_state,
        native_preroll_state == 0u ? "true" : "false",
        (unsigned long)barn_view, airplane_complete,
        (unsigned long)mode_count,
        (unsigned int)loaded, (unsigned int)opened,
        (long)InterlockedCompareExchange(&manager_tick_count, 0, 0));
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_scheduler_watchdog(const char *stage)
{
    char line[320];
    int size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,\"protocol\":\"miel-vliegt-native-scheduler\","
        "\"stage\":\"%s\",\"thread_id\":%lu,\"engine_thread_id\":%ld,"
        "\"manager_ticks\":%ld,\"manager_renders\":%ld,"
        "\"camera_commits\":%ld,\"session_state\":%u}\r\n",
        stage, (unsigned long)GetCurrentThreadId(),
        (long)InterlockedCompareExchange(&engine_thread_id, 0, 0),
        (long)InterlockedCompareExchange(&manager_tick_count, 0, 0),
        (long)InterlockedCompareExchange(&manager_render_count, 0, 0),
        (long)InterlockedCompareExchange(&camera_commit_count, 0, 0),
        (unsigned int)session_state);
    if (size > 0 && (size_t)size < sizeof(line)) {
        append_record(line, (DWORD)size);
        flush_trace();
    }
}

static DWORD WINAPI session_controller_thread(LPVOID ignored)
{
    DWORD index;
    char diagnostics[2] = {0};
    BOOL diagnostics_enabled =
        GetEnvironmentVariableA("MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS",
                                diagnostics, sizeof(diagnostics)) == 1u &&
        diagnostics[0] == '1';
    (void)ignored;
    if (diagnostics_enabled) emit_scheduler_watchdog("controller_started");
    for (index = 0u; index < 90000u; ++index) {
        Sleep(10u);
        /* Pre-activation login unblock. Headless the game parks at
           login-pending: Manager::Tick never fires, so the tick-gated
           auto-login (dispatch_native_capture_login_on_manager_tick ->
           send_login_submit_input) can never run and the main loop never
           begins ticking. This controller thread is NOT tick-gated, so
           synthesize the same Enter submit a few times early, stopping as
           soon as login-activation is observed. send_login_submit_input is a
           bare SendInput (Enter scancode 0x1c) with no window/lock
           prerequisites, safe from this thread. */
        if ((index == 200u || index == 500u || index == 900u ||
             index == 1500u || index == 2500u || index == 4000u) &&
            login_activation_event &&
            WaitForSingleObject(login_activation_event, 0u) != WAIT_OBJECT_0) {
            BOOL sent = send_login_submit_input();
            if (diagnostics_enabled) {
                emit_scheduler_watchdog(
                    sent ? "login_autosubmit_sent" : "login_autosubmit_failed");
            }
        }
        if (diagnostics_enabled && index % 1000u == 999u) {
            emit_scheduler_watchdog("watchdog");
        }
        /* Always-on (not diagnostics-gated) time-series of the bootstrap
           state, so the artifact shows whether the game ever progresses:
           does the application singleton construct, does manager_tick_count
           ever leave 0, does login-activation ever come. Re-emit the full
           bootstrap snapshot at 10s/30s/60s/120s. The 3-line-then-silence
           observer log left it ambiguous whether the game is hard-stalled
           pre-application or merely un-activated. */
        if (index == 1000u || index == 3000u ||
            index == 6000u || index == 12000u) {
            emit_bootstrap_diagnostic();
            flush_trace();
        }
        if (session_state == SESSION_COMPLETE ||
            session_state == SESSION_FAILED) break;
    }
    return 0u;
}

static BOOL calibration_bootstrap_manager_ready(DWORD expected_manager)
{
    LONG mode_set_manager = InterlockedCompareExchange(
        &late_bootstrap_manager_address, 0, 0);
    DWORD application;
    DWORD manager = 0u, manager_application = 0u;
    if (expected_manager != 0u) {
        return mode_set_manager == (LONG)expected_manager;
    }
    application = (DWORD)(ULONG_PTR)(
        (ApplicationGetterFunction)(ULONG_PTR)APPLICATION_GETTER)();
    return application != 0u &&
        read_pointer(application, 0x1acu, &manager) && manager != 0u &&
        read_pointer(manager, 0x10cu, &manager_application) &&
        manager_application == application;
}

static BOOL validate_calibration_manager_identity(DWORD manager_address)
{
    DWORD application = (DWORD)(ULONG_PTR)(
        (ApplicationGetterFunction)(ULONG_PTR)APPLICATION_GETTER)();
    DWORD rooted_manager = 0u, manager_application = 0u;
    LONG expected_manager = InterlockedCompareExchange(
        &late_bootstrap_manager_address, 0, 0);
    if (application == 0u || manager_address == 0u ||
        expected_manager == 0 ||
        expected_manager != (LONG)manager_address ||
        !read_pointer(application, 0x1acu, &rooted_manager) ||
        rooted_manager != manager_address ||
        !read_pointer(manager_address, 0x10cu, &manager_application) ||
        manager_application != application) {
        return FALSE;
    }
    InterlockedExchange(&calibration_manager_identity_validated, 1);
    return TRUE;
}

static DWORD WINAPI late_bootstrap_retry_thread(LPVOID ignored)
{
    HANDLE waits[2] = {failure_event, late_bootstrap_event};
    (void)ignored;
    for (;;) {
        DWORD manager = (DWORD)InterlockedCompareExchange(
            &late_bootstrap_manager_address, 0, 0);
        DWORD wait_result;
        if (manager == 0u && calibration_bootstrap_manager_ready(0u)) {
            if (complete_observer_bootstrap(manager) ||
                session_state == SESSION_FAILED) {
                return 0u;
            }
        }
        wait_result = WaitForMultipleObjects(
            2u, waits, FALSE, LATE_BOOTSTRAP_RETRY_MS);
        if (wait_result == WAIT_OBJECT_0 || wait_result == WAIT_FAILED) {
            if (wait_result == WAIT_FAILED) {
                session_fail("late_bootstrap_wait_contract");
            }
            return 0u;
        }
        if (wait_result != WAIT_OBJECT_0 + 1u &&
            wait_result != WAIT_TIMEOUT) {
            session_fail("late_bootstrap_wait_contract");
            return 0u;
        }
    }
}

static BOOL application_identity_matches(DWORD application)
{
    const char *name;
    char copy[7] = {0};
    int id = ((UserGetIdFunction)(ULONG_PTR)USER_GET_ID)(
        (void *)(ULONG_PTR)application);
    name = ((UserGetNameFunction)(ULONG_PTR)USER_GET_NAME)(
        (void *)(ULONG_PTR)application);
    return id == 0 && name != NULL &&
        copy_readable(name, (BYTE *)copy, sizeof(copy)) == sizeof(copy) &&
        memcmp(copy, "MVO_CI", 6u) == 0 && copy[6] == '\0';
}

static BOOL canonical_profile_state(DWORD application, DWORD login_address)
{
    int id = ((UserGetIdFunction)(ULONG_PTR)USER_GET_ID)(
        (void *)(ULONG_PTR)application);
    char input[7] = {0};
    DWORD input_length = 0u;
    BYTE editing = 0u;
    if (id == -1) return TRUE;
    return id == 0 &&
        read_byte(login_address, 0xd4u, &editing) && editing == 1u &&
        copy_readable((const void *)(ULONG_PTR)(login_address + 0xd5u),
                      (BYTE *)input, sizeof(input)) == sizeof(input) &&
        copy_readable((const void *)(ULONG_PTR)(login_address + 0x1d8u),
                      (BYTE *)&input_length,
                      sizeof(input_length)) == sizeof(input_length) &&
        input_length == 6u && memcmp(input, "MVO_CI", 6u) == 0 &&
        input[6] == '\0';
}

static BOOL flight_native_preroll_pending(DWORD flight_address)
{
    BYTE contact_sound_initialized = 0xffu;
    return flight_address != 0u &&
        read_byte(flight_address, 0x124u, &contact_sound_initialized) &&
        contact_sound_initialized == 0u;
}

static BOOL canonical_session_root(DWORD manager_address, DWORD *application_out)
{
    DWORD application = (DWORD)(ULONG_PTR)(
        (ApplicationGetterFunction)(ULONG_PTR)APPLICATION_GETTER)();
    DWORD rooted_manager = 0u;
    DWORD manager_application = 0u;
    if (application == 0u ||
        !read_pointer(application, 0x1acu, &rooted_manager) ||
        !read_pointer(manager_address, 0x10cu, &manager_application) ||
        rooted_manager != manager_address || manager_application != application) {
        return FALSE;
    }
    *application_out = application;
    return TRUE;
}

static BOOL exact_mygghanget_state(DWORD manager_address, DWORD *state_out)
{
    DWORD current = 0u;
    BYTE loaded = 0u, opened = 0u, barn_entry = 0xffu;
    void *resolved = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
        (void *)(ULONG_PTR)manager_address, "mode_mygghanget");
    return resolved != NULL &&
        read_pointer(manager_address, 0x18cu, &current) &&
        current == (DWORD)(ULONG_PTR)resolved &&
        read_byte(current, 0x14u, &loaded) && loaded == 1u &&
        read_byte(current, 0x15u, &opened) && opened == 1u &&
        read_byte(current, 0x999u, &barn_entry) && barn_entry == 0u &&
        copy_readable((const void *)(ULONG_PTR)(current + 0x8dcu),
                      (BYTE *)state_out, sizeof(*state_out)) ==
            sizeof(*state_out);
}

static BOOL exact_mygghanget_departure_transition(DWORD manager_address,
                                                   DWORD *caller_site_out)
{
    DWORD index, matches = 0u, caller_site = 0u;
    for (index = 0u; index < MODE_TRANSITION_LIMIT; ++index) {
        ModeTransitionObservation *transition = &mode_transitions[index];
        if (InterlockedCompareExchange(&transition->state, 0, 0) >= 2 &&
            transition->manager_address == manager_address &&
            (transition->caller_site == 0x00425c2eu ||
             transition->caller_site == 0x004262eeu) &&
            transition->source_mode_valid &&
            strcmp(transition->source_mode, "mode_mygghanget") == 0 &&
            transition->requested_mode_valid &&
            strcmp(transition->requested_mode, "mode_fly") == 0) {
            ++matches;
            caller_site = transition->caller_site;
        }
    }
    if (matches != 1u) return FALSE;
    *caller_site_out = caller_site;
    return TRUE;
}

static BOOL exact_session_ready(DWORD manager_address)
{
    DWORD current = 0u, pending = 0u, application = 0u;
    DWORD mode_application = 0u, physics = 0u;
    DWORD registered_render_list = 0u, flight_render_list = 0u;
    DWORD flight_manager = 0u, flight_camera = 0u, flight_physics = 0u;
    BYTE loaded = 0u, opened = 0u;
    void *resolved = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
        (void *)(ULONG_PTR)manager_address, "mode_fly");
    if (!resolved ||
        !read_pointer(manager_address, 0x18cu, &current) ||
        !read_pointer(manager_address, 0x190u, &pending) ||
        !canonical_session_root(manager_address, &application) ||
        !read_pointer(manager_address, 0x154u, &physics) ||
        !read_pointer(manager_address, 0x174u, &registered_render_list) ||
        current != (DWORD)(ULONG_PTR)resolved || pending != 0u ||
        !read_byte(current, 0x14u, &loaded) || loaded != 1u ||
        !read_byte(current, 0x15u, &opened) || opened != 1u ||
        !read_pointer(current, 0x4u, &mode_application) ||
        !read_pointer(current, 0x68u, &flight_render_list) ||
        !read_pointer(current, 0x54u, &flight_manager) ||
        !read_pointer(current, 0x58u, &flight_camera) ||
        !read_pointer(current, 0x64u, &flight_physics) ||
        mode_application != application || flight_manager != manager_address ||
        registered_render_list == 0u ||
        registered_render_list != flight_render_list ||
        flight_camera == 0u || flight_physics == 0u ||
        flight_physics != physics || !flight_native_preroll_pending(physics) ||
        !application_identity_matches(application)) {
        return FALSE;
    }
    return TRUE;
}

static BOOL exact_barn_ready(DWORD manager_address, DWORD *view_out)
{
    DWORD current = 0u, pending = 0u, application = 0u;
    DWORD mode_application = 0u, barn_manager = 0u, view = 0u;
    BYTE loaded = 0u, opened = 0u;
    void *resolved = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
        (void *)(ULONG_PTR)manager_address, "mode_barn");
    return resolved != NULL &&
        read_pointer(manager_address, 0x18cu, &current) &&
        read_pointer(manager_address, 0x190u, &pending) &&
        canonical_session_root(manager_address, &application) &&
        current == (DWORD)(ULONG_PTR)resolved && pending == 0u &&
        read_byte(current, 0x14u, &loaded) && loaded == 1u &&
        read_byte(current, 0x15u, &opened) && opened == 1u &&
        read_pointer(current, 0x4u, &mode_application) &&
        read_pointer(current, 0x15cu, &barn_manager) &&
        copy_readable((const void *)(ULONG_PTR)(current + 0x190u),
                      (BYTE *)&view, sizeof(view)) == sizeof(view) &&
        mode_application == application && barn_manager == manager_address &&
        application_identity_matches(application) &&
        ((*view_out = view), TRUE);
}

static BOOL barn_airplane_is_complete(DWORD manager_address)
{
    DWORD current = 0u, airplane = 0u;
    void *barn = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
        (void *)(ULONG_PTR)manager_address, "mode_barn");
    return barn != NULL &&
        read_pointer(manager_address, 0x18cu, &current) &&
        current == (DWORD)(ULONG_PTR)barn &&
        read_pointer(current, 0x160u, &airplane) && airplane != 0u &&
        ((AirplaneCompleteFunction)(ULONG_PTR)AIRPLANE_COMPLETE)(
            (void *)(ULONG_PTR)airplane) != 0u;
}

static BOOL observe_native_flight_bootstrap(DWORD manager_address)
{
    DWORD current = 0u, pending = 0u, state = INVALID_ID;
    DWORD departure_caller_site = 0u;
    DWORD barn, mygghanget, flight;
    BOOL sampled_keys_valid = FALSE;
    BYTE sampled_keys = sampled_key_mask(
        manager_address + 0x108u, &sampled_keys_valid);
    if (bootstrap_faster_input_down && sampled_keys_valid &&
        (sampled_keys & REPLAY_KEY_SHIFT) != 0u) {
        bootstrap_faster_sample_observed = TRUE;
    }
    if (!read_pointer(manager_address, 0x18cu, &current) ||
        !read_pointer(manager_address, 0x190u, &pending)) {
        session_fail("bootstrap_mode_read_contract");
        return FALSE;
    }
    barn = (DWORD)(ULONG_PTR)((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
        (void *)(ULONG_PTR)manager_address, "mode_barn");
    mygghanget = (DWORD)(ULONG_PTR)(
        (ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
            (void *)(ULONG_PTR)manager_address, "mode_mygghanget");
    flight = (DWORD)(ULONG_PTR)((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
        (void *)(ULONG_PTR)manager_address, "mode_fly");
    if (barn == 0u || mygghanget == 0u || flight == 0u) {
        session_fail("bootstrap_mode_resolution_contract");
        return FALSE;
    }
    if (current == barn) {
        if (pending != 0u && pending != mygghanget) {
            session_fail("bootstrap_barn_pending_contract");
        }
        return FALSE;
    }
    if (current == mygghanget) {
        if ((pending != 0u && pending != flight) ||
            !exact_mygghanget_state(manager_address, &state)) {
            session_fail("bootstrap_mygghanget_mode_contract");
            return FALSE;
        }
        if (flight_bootstrap_phase == BOOTSTRAP_WAIT_MYGGHANGET_STATE_FIVE) {
            if (state != 5u) {
                session_fail("bootstrap_mygghanget_entry_state_contract");
                return FALSE;
            }
            flight_bootstrap_phase = BOOTSTRAP_WAIT_MYGGHANGET_DEPARTURE;
            emit_session("navigating", "native_mygghanget_state_five");
            if (!send_bootstrap_faster_input(TRUE)) {
                session_fail("bootstrap_start_engine_input_down");
                return FALSE;
            }
            emit_session("navigating", "native_mygghanget_start_engine_input_down");
        } else if (flight_bootstrap_phase != BOOTSTRAP_WAIT_MYGGHANGET_DEPARTURE) {
            session_fail("bootstrap_mygghanget_phase_contract");
            return FALSE;
        }
        if (state != 5u && state != 4u && state != 0u) {
            session_fail("bootstrap_mygghanget_state_contract");
            return FALSE;
        }
        if (state != 5u && bootstrap_faster_input_down) {
            if (!bootstrap_faster_sample_observed) {
                session_fail("bootstrap_start_engine_sample_contract");
                return FALSE;
            }
            if (!send_bootstrap_faster_input(FALSE)) {
                session_fail("bootstrap_start_engine_input_up");
                return FALSE;
            }
            emit_session("navigating", "native_mygghanget_start_engine_input_up");
        }
        if (state == 0u && !mygghanget_state_zero_observed) {
            mygghanget_state_zero_observed = TRUE;
            emit_session("navigating", "native_mygghanget_state_zero");
        }
        return FALSE;
    }
    if (current == flight) {
        if (!bootstrap_faster_sample_observed) {
            session_fail("bootstrap_start_engine_sample_contract");
            return FALSE;
        }
        if (!send_bootstrap_faster_input(FALSE)) {
            session_fail("bootstrap_start_engine_input_up");
            return FALSE;
        }
        if (pending != 0u ||
            flight_bootstrap_phase != BOOTSTRAP_WAIT_MYGGHANGET_DEPARTURE ||
            !exact_mygghanget_departure_transition(
                manager_address, &departure_caller_site) ||
            (departure_caller_site == 0x00425c2eu &&
             !mygghanget_state_zero_observed) ||
            (departure_caller_site == 0x004262eeu &&
             mygghanget_state_zero_observed)) {
            session_fail("bootstrap_mygghanget_to_flight_contract");
            return FALSE;
        }
        if (departure_caller_site == 0x004262eeu) {
            emit_session("navigating", "native_mygghanget_departure_commit");
        }
        return TRUE;
    }
    session_fail("bootstrap_unexpected_mode_contract");
    return FALSE;
}

static BOOL body_mode_allowed(const char *mode_name)
{
    DWORD index;
    for (index = 0u; index < BODY_MODE_COUNT; ++index) {
        if (strcmp(mode_name, BODY_MODE_ALLOWLIST[index]) == 0) return TRUE;
    }
    return FALSE;
}

static BOOL registry_name_matches(DWORD record, const char *expected)
{
    char name[256];
    if (copy_readable((const void *)(ULONG_PTR)record, (BYTE *)name,
                      sizeof(name)) != sizeof(name) ||
        memchr(name, '\0', sizeof(name)) == NULL) return FALSE;
    return strcmp(name, expected) == 0;
}

static BOOL resolve_registered_engine_mode_callback(
    DWORD application, DWORD manager_address,
    void **callback_object_out, EngineCommandFunction *callback_out)
{
    DWORD registry = 0u, record = 0u, next = 0u;
    DWORD command_id = 0u, callback_object = 0u;
    DWORD callback_vtable = 0u, callback_address = 0u;
    DWORD count;
    if (!read_pointer(application, 0x19cu, &registry) || registry == 0u ||
        !read_pointer(registry, 0x40u, &record) || record == 0u) return FALSE;
    for (count = 0u; count < 128u && record != 0u; ++count) {
        if (registry_name_matches(record, ENGINE_MODE_COMMAND_NAME)) break;
        if (!read_pointer(record, 0x108u, &next) || next == record) return FALSE;
        record = next;
    }
    if (record == 0u || count == 128u ||
        !read_pointer(record, 0x100u, &command_id) ||
        !read_pointer(record, 0x104u, &callback_object) ||
        command_id != ENGINE_MODE_COMMAND_ID ||
        callback_object != manager_address + 0x130u ||
        !read_pointer(callback_object, 0u, &callback_vtable) ||
        !read_pointer(callback_vtable, 0u, &callback_address) ||
        callback_address != (DWORD)(ULONG_PTR)ENGINE_MODE_CALLBACK) {
        return FALSE;
    }
    *callback_object_out = (void *)(ULONG_PTR)callback_object;
    *callback_out = (EngineCommandFunction)(ULONG_PTR)callback_address;
    return TRUE;
}

static const char *body_return_mode_name(void)
{
    return strcmp(body_mode_name, "mode_barn") == 0
        ? "mode_login" : "mode_barn";
}

static const BodyModeLifecycle *body_mode_for_name(const char *mode_name)
{
    DWORD index;
    for (index = 0u; index < BODY_MODE_COUNT; ++index) {
        if (strcmp(BODY_MODE_LIFECYCLES[index].mode_name, mode_name) == 0) {
            return &BODY_MODE_LIFECYCLES[index];
        }
    }
    return NULL;
}

static void sync_body_phase_observation(void)
{
    const BodyModeLifecycle *mode = body_mode_for_name(body_mode_name);
    DWORD mode_index;
    if (!mode) return;
    mode_index = (DWORD)(mode - BODY_MODE_LIFECYCLES);
    memcpy(body_dispatch.phase_counts, body_lifecycle_counts[mode_index],
           sizeof(body_dispatch.phase_counts));
    memcpy(body_dispatch.last_leave_ticks,
           body_lifecycle_last_leave_ticks[mode_index],
           sizeof(body_dispatch.last_leave_ticks));
}

static BOOL body_core_is_ready(void)
{
    sync_body_phase_observation();
    return body_dispatch.phase_counts[BODY_PHASE_LOAD] >= 1u &&
        body_dispatch.phase_counts[BODY_PHASE_OPEN] >= 1u &&
        body_dispatch.phase_counts[BODY_PHASE_TICK] >= 1u &&
        body_dispatch.phase_counts[BODY_PHASE_RENDER] >= 1u &&
        body_dispatch.last_leave_ticks[BODY_PHASE_TICK] >=
            body_dispatch.target_activation_tick &&
        body_dispatch.last_leave_ticks[BODY_PHASE_RENDER] >=
            body_dispatch.target_activation_tick;
}

static BOOL body_position_probe_ready(DWORD tick)
{
    LONG records;
    if (!body_position_probe_enabled) return TRUE;
    records = InterlockedCompareExchange(
        &position_character_record_count, 0, 0);
    if (records > 0) return TRUE;
    if (body_position_probe_start_tick == INVALID_ID) {
        body_position_probe_start_tick = tick;
        emit_session("diagnostic", "native_position_wait_started");
        return FALSE;
    }
    /* Let the original common-location controller reach and start its loaded
     * UDSP root.  A DEF placement is output data, not a hit-test coordinate;
     * this probe therefore performs no input synthesis and no state writes. */
    if (tick - body_position_probe_start_tick > 3000u) {
        body_dispatch_fail("body_position_probe_timeout_contract");
    }
    return FALSE;
}

static BOOL body_mode_is_loaded_and_opened(DWORD mode_address)
{
    BYTE loaded = 0u, opened = 0u;
    return mode_address != 0u &&
        read_byte(mode_address, 0x14u, &loaded) && loaded == 1u &&
        read_byte(mode_address, 0x15u, &opened) && opened == 1u;
}

static BOOL write_body_only_receipt(DWORD manager_address)
{
    HANDLE file;
    DWORD current = 0u, pending = 0u, written = 0u;
    DWORD target_resolved = 0u, return_resolved = 0u, barn_resolved = 0u;
    DWORD application = 0u;
    DWORD expected_unloads = strcmp(body_mode_name, "mode_fly") == 0 ? 0u : 1u;
    const char *return_mode = body_return_mode_name();
    const char *flight_status = expected_unloads == 0u ? "INCOMPLETE" : "PASS";
    const char *unload_observed = expected_unloads == 0u ? "false" : "true";
    const char *unload_policy = expected_unloads == 0u
        ? "SKIPPED_MODE_FLY" : "MANAGER_COMMIT";
    const char *missing_phases = expected_unloads == 0u
        ? "[\"UNLOAD\"]" : "[]";
    const char *lifecycle_complete = expected_unloads == 0u ? "false" : "true";
    const char *entry_effect = strcmp(body_mode_name, "mode_barn") == 0
        ? "SAME_MODE_NOOP" : "PENDING_TARGET";
    char entry_pending[MODE_NAME_SIZE + 3u];
    char executable_hash[65];
    char json[4096];
    int size;
    sync_body_phase_observation();
    if (strcmp(body_mode_name, "mode_barn") == 0) {
        memcpy(entry_pending, "null", sizeof("null"));
    } else if (snprintf(entry_pending, sizeof(entry_pending), "\"%s\"",
                        body_mode_name) <= 0) {
        return FALSE;
    }
    if (!canonical_session_root(manager_address, &application) ||
        application == 0u ||
        !read_pointer(manager_address, 0x18cu, &current) ||
        !read_pointer(manager_address, 0x190u, &pending) ||
        current != body_dispatch.return_address || pending != 0u ||
        !body_mode_is_loaded_and_opened(current)) return FALSE;
    target_resolved = (DWORD)(ULONG_PTR)(
        (ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
            (void *)(ULONG_PTR)manager_address, body_mode_name);
    return_resolved = (DWORD)(ULONG_PTR)(
        (ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
            (void *)(ULONG_PTR)manager_address, return_mode);
    barn_resolved = (DWORD)(ULONG_PTR)(
        (ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
            (void *)(ULONG_PTR)manager_address, "mode_barn");
    if (target_resolved == 0u ||
        target_resolved != body_dispatch.target_address ||
        return_resolved == 0u ||
        return_resolved != body_dispatch.return_address ||
        barn_resolved == 0u ||
        barn_resolved != body_dispatch.entry_pre_current ||
        body_dispatch.entry_post_current != barn_resolved ||
        ((strcmp(body_mode_name, "mode_barn") == 0 &&
          body_dispatch.entry_post_pending != 0u) ||
         (strcmp(body_mode_name, "mode_barn") != 0 &&
          body_dispatch.entry_post_pending != target_resolved)) ||
        body_dispatch.return_post_current != target_resolved ||
        body_dispatch.return_post_pending != return_resolved ||
        body_dispatch.callback_count != 2u ||
        body_dispatch.manager_address != manager_address ||
        body_dispatch.dispatch_thread_id != GetCurrentThreadId() ||
        (DWORD)InterlockedCompareExchange(&engine_thread_id, 0, 0) !=
            GetCurrentThreadId() ||
        body_dispatch.phase_counts[BODY_PHASE_CLOSE] != 1u ||
        body_dispatch.phase_counts[BODY_PHASE_UNLOAD] != expected_unloads ||
        !(body_dispatch.entry_dispatch_tick <=
              body_dispatch.target_activation_tick &&
          body_dispatch.target_activation_tick <=
              body_dispatch.core_ready_tick &&
          body_dispatch.core_ready_tick ==
              body_dispatch.return_dispatch_tick &&
          body_dispatch.return_dispatch_tick <=
              body_dispatch.return_activation_tick) ||
        body_dispatch.last_leave_ticks[BODY_PHASE_LOAD] >
            body_dispatch.core_ready_tick ||
        body_dispatch.last_leave_ticks[BODY_PHASE_OPEN] >
            body_dispatch.core_ready_tick ||
        body_dispatch.last_leave_ticks[BODY_PHASE_TICK] >
            body_dispatch.core_ready_tick ||
        body_dispatch.last_leave_ticks[BODY_PHASE_RENDER] >
            body_dispatch.core_ready_tick ||
        !body_core_is_ready() ||
        diagnostic_skip_target != NULL || diagnostic_session_only) {
        return FALSE;
    }
    encode_sha256(EXPECTED_EXE_SHA256, executable_hash);
    size = snprintf(
        json, sizeof(json),
        "{\"schema\":2,"
        "\"protocol\":\"miel-vliegt-native-body-dispatch\","
        "\"status\":\"%s\",\"evidence_scope\":\"BODY_ONLY\","
        "\"natural_transition_evidence\":false,"
        "\"debug_skip_used\":false,"
        "\"executable_sha256\":\"%s\","
        "\"requested_mode\":\"%s\",\"return_mode\":\"%s\","
        "\"command\":{\"name\":\"engine_mode\",\"id\":15,"
        "\"dispatch\":\"registered-command-callback\"},"
        "\"callback_count\":2,\"manager_thread\":true,"
        "\"dispatch_thread\":%lu,"
        "\"ticks\":{\"entry_dispatch\":%lu,"
        "\"target_activation\":%lu,\"core_ready\":%lu,"
        "\"return_dispatch\":%lu,\"return_activation\":%lu},"
        "\"entry\":{\"pre\":{\"manager_canonical\":true,"
        "\"current_mode\":\"mode_barn\",\"pending_null\":true,"
        "\"target_resolved_before_mutation\":true,"
        "\"registry_record_resolved\":true},"
        "\"post\":{\"current_mode\":\"mode_barn\","
        "\"pending_mode\":%s,\"dispatch_effect\":\"%s\"},"
        "\"activation\":{\"current_mode\":\"%s\","
        "\"pending_null\":true,\"loaded\":true,\"opened\":true}},"
        "\"core\":{\"paired_counts\":{\"LOAD\":%lu,\"OPEN\":%lu,"
        "\"TICK\":%lu,\"RENDER\":%lu},"
        "\"last_leave_ticks\":{\"LOAD\":%lu,\"OPEN\":%lu,"
        "\"TICK\":%lu,\"RENDER\":%lu},"
        "\"fresh_after_activation\":{\"TICK\":true,\"RENDER\":true},"
        "\"complete\":true},"
        "\"return\":{\"pre\":{\"current_mode\":\"%s\","
        "\"pending_null\":true,\"loaded\":true,\"opened\":true},"
        "\"post\":{\"current_mode\":\"%s\","
        "\"pending_mode\":\"%s\","
        "\"dispatch_effect\":\"PENDING_RETURN\"},"
        "\"activation\":{\"current_mode\":\"%s\","
        "\"pending_null\":true,\"loaded\":true,\"opened\":true}},"
        "\"teardown\":{\"close_pairs_delta\":1,"
        "\"unload_pairs_delta\":%lu,\"close_observed\":true,"
        "\"unload_observed\":%s,\"unload_policy\":\"%s\","
        "\"missing_phases\":%s,\"complete\":%s},"
        "\"lifecycle_complete\":%s}\n",
        flight_status, executable_hash, body_mode_name, return_mode,
        (unsigned long)body_dispatch.dispatch_thread_id,
        (unsigned long)body_dispatch.entry_dispatch_tick,
        (unsigned long)body_dispatch.target_activation_tick,
        (unsigned long)body_dispatch.core_ready_tick,
        (unsigned long)body_dispatch.return_dispatch_tick,
        (unsigned long)body_dispatch.return_activation_tick,
        entry_pending, entry_effect, body_mode_name,
        (unsigned long)body_dispatch.phase_counts[BODY_PHASE_LOAD],
        (unsigned long)body_dispatch.phase_counts[BODY_PHASE_OPEN],
        (unsigned long)body_dispatch.phase_counts[BODY_PHASE_TICK],
        (unsigned long)body_dispatch.phase_counts[BODY_PHASE_RENDER],
        (unsigned long)body_dispatch.last_leave_ticks[BODY_PHASE_LOAD],
        (unsigned long)body_dispatch.last_leave_ticks[BODY_PHASE_OPEN],
        (unsigned long)body_dispatch.last_leave_ticks[BODY_PHASE_TICK],
        (unsigned long)body_dispatch.last_leave_ticks[BODY_PHASE_RENDER],
        body_mode_name, body_mode_name, return_mode, return_mode,
        (unsigned long)expected_unloads, unload_observed, unload_policy,
        missing_phases, lifecycle_complete, lifecycle_complete);
    if (size <= 0 || (size_t)size >= sizeof(json)) return FALSE;
    file = CreateFileA(body_receipt_path, GENERIC_WRITE, 0u, NULL, CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    if (!WriteFile(file, json, (DWORD)size, &written, NULL) ||
        written != (DWORD)size || !FlushFileBuffers(file)) {
        CloseHandle(file);
        DeleteFileA(body_receipt_path);
        return FALSE;
    }
    return CloseHandle(file);
}

static void body_dispatch_fail(const char *reason)
{
    InterlockedExchange(&body_callback_active, 0);
    InterlockedExchange(&body_dispatch_state, BODY_DISPATCH_FAILED);
    session_fail(reason);
}

static void dispatch_body_mode_on_manager_tick(DWORD manager_address)
{
    LONG state = InterlockedCompareExchange(&body_dispatch_state, 0, 0);
    DWORD current = 0u, pending = 0u, application = 0u, barn_view = 0u;
    DWORD target_address, return_address;
    DWORD tick = (DWORD)InterlockedCompareExchange(&manager_tick_count, 0, 0);
    DWORD expected_unloads = strcmp(body_mode_name, "mode_fly") == 0 ? 0u : 1u;
    const char *return_mode = body_return_mode_name();
    ModeTransitionObservation *barn_transition = &mode_transitions[1];
    void *callback_object = NULL;
    EngineCommandFunction callback = NULL;
    if (state < BODY_DISPATCH_DISABLED || state > BODY_DISPATCH_FAILED ||
        state == BODY_DISPATCH_IN_ENTRY_CALLBACK ||
        state == BODY_DISPATCH_IN_RETURN_CALLBACK) {
        body_dispatch_fail("body_state_contract");
        return;
    }
    if (state == BODY_DISPATCH_DISABLED || state == BODY_DISPATCH_COMPLETE ||
        state == BODY_DISPATCH_FAILED) return;
    if (state != BODY_DISPATCH_WAIT_BARN &&
        (body_dispatch.manager_address != manager_address ||
         body_dispatch.dispatch_thread_id != GetCurrentThreadId() ||
         (DWORD)InterlockedCompareExchange(&engine_thread_id, 0, 0) !=
            GetCurrentThreadId())) {
        body_dispatch_fail("body_manager_thread_contract");
        return;
    }
    if (state == BODY_DISPATCH_WAIT_TARGET_ACTIVATION) {
        if (!read_pointer(manager_address, 0x18cu, &current) ||
            !read_pointer(manager_address, 0x190u, &pending)) {
            body_dispatch_fail("body_target_activation_read_contract");
        } else if (current == body_dispatch.target_address && pending == 0u) {
            if (!body_mode_is_loaded_and_opened(current)) {
                body_dispatch_fail("body_target_activation_contract");
                return;
            }
            body_dispatch.target_activation_tick = tick;
            InterlockedExchange(&body_dispatch_state, BODY_DISPATCH_WAIT_CORE);
        } else if (!((current == body_dispatch.entry_pre_current &&
                      pending == body_dispatch.target_address))) {
            body_dispatch_fail("body_target_transition_contract");
        }
        return;
    }
    if (state == BODY_DISPATCH_WAIT_CORE) {
        if (!read_pointer(manager_address, 0x18cu, &current) ||
            !read_pointer(manager_address, 0x190u, &pending) ||
            current != body_dispatch.target_address || pending != 0u ||
            !body_mode_is_loaded_and_opened(current)) {
            body_dispatch_fail("body_core_mode_contract");
            return;
        }
        if (!body_core_is_ready() || !body_position_probe_ready(tick)) return;
        if (!canonical_session_root(manager_address, &application) ||
            !resolve_registered_engine_mode_callback(
                application, manager_address, &callback_object, &callback)) {
            body_dispatch_fail("body_return_registry_contract");
            return;
        }
        return_address = (DWORD)(ULONG_PTR)(
            (ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
                (void *)(ULONG_PTR)manager_address, return_mode);
        if (return_address == 0u ||
            return_address == body_dispatch.target_address) {
            body_dispatch_fail("body_return_target_contract");
            return;
        }
        body_dispatch.return_address = return_address;
        body_dispatch.core_ready_tick = tick;
        body_dispatch.return_dispatch_tick = tick;
        InterlockedExchange(
            &body_dispatch_state, BODY_DISPATCH_IN_RETURN_CALLBACK);
        InterlockedExchange(&body_callback_active, 1);
        callback(callback_object, ENGINE_MODE_COMMAND_ID, return_mode);
        InterlockedExchange(&body_callback_active, 0);
        body_dispatch.callback_count = 2u;
        if (!read_pointer(manager_address, 0x18cu,
                          &body_dispatch.return_post_current) ||
            !read_pointer(manager_address, 0x190u,
                          &body_dispatch.return_post_pending) ||
            body_dispatch.return_post_current !=
                body_dispatch.target_address ||
            body_dispatch.return_post_pending != return_address) {
            body_dispatch_fail("body_return_postcondition_contract");
            return;
        }
        InterlockedExchange(
            &body_dispatch_state, BODY_DISPATCH_WAIT_RETURN_ACTIVATION);
        return;
    }
    if (state == BODY_DISPATCH_WAIT_RETURN_ACTIVATION) {
        if (!read_pointer(manager_address, 0x18cu, &current) ||
            !read_pointer(manager_address, 0x190u, &pending)) {
            body_dispatch_fail("body_return_activation_read_contract");
        } else if (current == body_dispatch.return_address && pending == 0u) {
            if (!body_mode_is_loaded_and_opened(current)) {
                body_dispatch_fail("body_return_activation_contract");
                return;
            }
            body_dispatch.return_activation_tick = tick;
            InterlockedExchange(
                &body_dispatch_state, BODY_DISPATCH_WAIT_TEARDOWN);
        } else if (!(current == body_dispatch.target_address &&
                     pending == body_dispatch.return_address)) {
            body_dispatch_fail("body_return_transition_contract");
        }
        return;
    }
    if (state == BODY_DISPATCH_WAIT_TEARDOWN) {
        if (!read_pointer(manager_address, 0x18cu, &current) ||
            !read_pointer(manager_address, 0x190u, &pending) ||
            current != body_dispatch.return_address || pending != 0u) {
            body_dispatch_fail("body_teardown_mode_contract");
            return;
        }
        sync_body_phase_observation();
        if (body_dispatch.phase_counts[BODY_PHASE_CLOSE] > 1u ||
            body_dispatch.phase_counts[BODY_PHASE_UNLOAD] > expected_unloads) {
            body_dispatch_fail("body_teardown_count_contract");
        } else if (body_dispatch.phase_counts[BODY_PHASE_CLOSE] == 1u &&
            body_dispatch.phase_counts[BODY_PHASE_UNLOAD] == expected_unloads) {
            if (!write_body_only_receipt(manager_address)) {
                body_dispatch_fail("body_receipt_contract");
            } else {
                InterlockedExchange(
                    &body_dispatch_state, BODY_DISPATCH_COMPLETE);
            }
        }
        return;
    }
    if (state != BODY_DISPATCH_WAIT_BARN ||
        session_state != SESSION_DISPATCHED ||
        InterlockedCompareExchange(&login_activation_observed, 0, 0) != 1 ||
        barn_transition->id != 1u || barn_transition->state != 3 ||
        !barn_transition->requested_mode_valid ||
        strcmp(barn_transition->requested_mode, "mode_barn") != 0 ||
        !exact_barn_ready(manager_address, &barn_view)) return;
    (void)barn_view;
    if (!canonical_session_root(manager_address, &application) ||
        !read_pointer(manager_address, 0x18cu, &current) || current == 0u ||
        !read_pointer(manager_address, 0x190u, &pending) || pending != 0u) {
        body_dispatch_fail("body_precondition_contract");
        return;
    }
    target_address = (DWORD)(ULONG_PTR)(
        (ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
            (void *)(ULONG_PTR)manager_address, body_mode_name);
    if (target_address == 0u ||
        !resolve_registered_engine_mode_callback(
            application, manager_address, &callback_object, &callback)) {
        body_dispatch_fail("body_target_or_registry_contract");
        return;
    }
    memset(&body_dispatch, 0, sizeof(body_dispatch));
    body_dispatch.manager_address = manager_address;
    body_dispatch.target_address = target_address;
    body_dispatch.entry_pre_current = current;
    body_dispatch.dispatch_thread_id = GetCurrentThreadId();
    body_dispatch.entry_dispatch_tick = tick;
    body_dispatch.callback_count = 1u;
    InterlockedExchange(
        &body_dispatch_state, BODY_DISPATCH_IN_ENTRY_CALLBACK);
    InterlockedExchange(&body_callback_active, 1);
    callback(callback_object, ENGINE_MODE_COMMAND_ID, body_mode_name);
    InterlockedExchange(&body_callback_active, 0);
    if (!read_pointer(manager_address, 0x18cu,
                      &body_dispatch.entry_post_current) ||
        !read_pointer(manager_address, 0x190u,
                      &body_dispatch.entry_post_pending) ||
        body_dispatch.entry_post_current != current ||
        ((strcmp(body_mode_name, "mode_barn") == 0 &&
          body_dispatch.entry_post_pending != 0u) ||
         (strcmp(body_mode_name, "mode_barn") != 0 &&
          body_dispatch.entry_post_pending != target_address))) {
        body_dispatch_fail("body_postcondition_contract");
        return;
    }
    InterlockedExchange(
        &body_dispatch_state, BODY_DISPATCH_WAIT_TARGET_ACTIVATION);
}

static void native_capture_driver_fail(const char *reason)
{
    InterlockedExchange(
        &native_capture_driver_state, NATIVE_CAPTURE_DRIVER_FAILED);
    session_fail(reason);
}

static BOOL write_native_capture_driver_receipt(void)
{
    HANDLE file;
    DWORD written = 0u;
    char json[4096];
    int size;
    const MvdsFinalMissionReadback *before =
        &native_capture_driver.before_readback;
    const MvdsFinalMissionReadback *hook =
        &native_capture_driver.hook_readback;
    const char *target_mode = native_dispatch_capture_target.driver_mode;
    const char *capture_session_id = mvds_capture_session_id();
    BOOL clean_v2 = native_dispatch_capture_target.capture_driver ==
        MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2;
    if (!clean_v2 && native_dispatch_capture_target.capture_driver !=
            MVDS_CAPTURE_DRIVER_MISSION_LOCATION_ENTER_V1) return FALSE;
    if (!target_mode || !capture_session_id ||
        native_capture_driver_receipt_path[0] == '\0' ||
        native_capture_driver.pre_current == 0u ||
        !mode_name_for_object(native_capture_driver.pre_current) ||
        strcmp(mode_name_for_object(native_capture_driver.pre_current),
               "mode_fly") != 0 ||
        native_capture_driver.flight_ready_tick == 0u ||
        (native_capture_driver.departure_caller_site != 0x00425c2eu &&
         native_capture_driver.departure_caller_site != 0x004262eeu) ||
        native_capture_driver.dispatch_tick <
            native_capture_driver.flight_ready_tick ||
        native_capture_driver.activation_tick <
            native_capture_driver.dispatch_tick ||
        native_capture_driver.capture_tick <
            native_capture_driver.activation_tick ||
        (clean_v2 &&
         (before->state == 3 || hook->state == 3 ||
          before->state != hook->state)) ||
        before->application_getter_address != 0x00405a20u ||
        before->mission_lookup_address != 0x004375e0u ||
        before->mission_complete_address != 0x00436090u ||
        hook->application_getter_address != 0x00405a20u ||
        hook->mission_lookup_address != 0x004375e0u ||
        hook->mission_complete_address != 0x00436090u) return FALSE;
    size = snprintf(
        json, sizeof(json),
        "{\"schema\":%d,"
        "\"protocol\":\"miel-vliegt-native-dispatch-driver-receipt\","
        "\"status\":\"PASS\","
        "\"driver\":\"%s\","
        "\"bootstrap\":{"
        "\"profile\":\"NATIVE_DISPATCH_DRIVER_V2\","
        "\"profileSha256\":\""
            NATIVE_CAPTURE_DRIVER_BOOTSTRAP_PROFILE_SHA256 "\","
        "\"scenarioSha256\":\""
            NATIVE_CAPTURE_DRIVER_SCENARIO_SHA256 "\","
        "\"initialUserSha256\":\""
            NATIVE_CAPTURE_DRIVER_INITIAL_USER_SHA256 "\"},"
        "\"targetSha256\":\"%s\","
        "\"naturalTransitionEvidence\":false,"
        "\"nativeProcessId\":%lu,\"captureSessionId\":\"%s\","
        "\"managerAddress\":%lu,"
        "\"entryPath\":\"NATIVE_BARN_MYGGHANGET_FLIGHT_THEN_ENGINE_MODE\","
        "\"sourceMode\":\"mode_fly\",\"sourceModeAddress\":%lu,"
        "\"targetMode\":\"%s\","
        "\"targetModeAddress\":%lu,"
        "\"callback\":{\"name\":\"engine_mode\",\"id\":15,"
        "\"address\":4317616},"
        "\"flightPrerequisite\":{\"departureCallerSite\":\"0x%08lx\","
        "\"flightReady\":true},"
        "\"ticks\":{\"flightReady\":%lu,\"dispatch\":%lu,"
        "\"activation\":%lu,"
        "\"capture\":%lu},"
        "\"missionReadback\":{"
        "\"before\":{\"state\":%d,\"missionPresent\":%s,"
        "\"missionAddress\":%lu,\"functions\":{"
        "\"applicationGetter\":4217376,\"missionLookup\":4421088,"
        "\"missionComplete\":4415632}},"
        "\"hook\":{\"state\":%d,\"missionPresent\":%s,"
        "\"missionAddress\":%lu,\"functions\":{"
        "\"applicationGetter\":4217376,\"missionLookup\":4421088,"
        "\"missionComplete\":4415632}}},"
        "\"semanticStateWritePolicy\":{"
        "\"policy\":\"NO_DIRECT_SEMANTIC_STATE_WRITES\","
        "\"loginUiBootstrapException\":true,\"mission\":false,"
        "\"selector\":false,\"root\":false,"
        "\"projectedValues\":false}}\r\n",
        clean_v2 ? 2 : 4,
        clean_v2 ? "GENERIC_LOCATION_CLEAN_V2"
                 : "MISSION_LOCATION_ENTER_V1",
        native_dispatch_capture_target.target_sha256,
        (unsigned long)GetCurrentProcessId(), capture_session_id,
        (unsigned long)native_capture_driver.manager_address,
        (unsigned long)native_capture_driver.pre_current, target_mode,
        (unsigned long)native_capture_driver.target_address,
        (unsigned long)native_capture_driver.departure_caller_site,
        (unsigned long)native_capture_driver.flight_ready_tick,
        (unsigned long)native_capture_driver.dispatch_tick,
        (unsigned long)native_capture_driver.activation_tick,
        (unsigned long)native_capture_driver.capture_tick,
        before->state, before->mission_present ? "true" : "false",
        (unsigned long)before->mission_address,
        hook->state, hook->mission_present ? "true" : "false",
        (unsigned long)hook->mission_address);
    if (size <= 0 || (size_t)size >= sizeof(json)) return FALSE;
    file = CreateFileA(
        native_capture_driver_receipt_path, GENERIC_WRITE, 0, NULL,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    if (!WriteFile(file, json, (DWORD)size, &written, NULL) ||
        written != (DWORD)size || !FlushFileBuffers(file)) {
        CloseHandle(file);
        DeleteFileA(native_capture_driver_receipt_path);
        return FALSE;
    }
    return CloseHandle(file);
}

static BOOL write_native_capture_traversal_receipt(void)
{
    HANDLE file;
    DWORD written = 0u;
    char json[2048];
    int size;
    const char *target_mode = native_dispatch_capture_target.driver_mode;
    const char *capture_session_id = mvds_capture_session_id();
    const char *driver_name;
    const char *entry_path;
    const char *source_mode;
    if (native_dispatch_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_BOOTSTRAP_TRAVERSAL_V1) {
        driver_name = "BOOTSTRAP_TRAVERSAL_V1";
        entry_path = "NATIVE_LOGIN_BARN_MYGGHANGET_TRAVERSAL";
        source_mode = "mode_barn";
    } else if (native_dispatch_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_MISSION_BARN_TRAVERSAL_V1) {
        driver_name = "MISSION_BARN_TRAVERSAL_V1";
        entry_path = "NATIVE_LOGIN_BARN_TRAVERSAL";
        source_mode = "mode_login";
    } else {
        return FALSE;
    }
    if (!target_mode || !capture_session_id ||
        native_capture_driver_receipt_path[0] == '\0' ||
        native_capture_driver.manager_address == 0u ||
        native_capture_driver.dispatch_tick == 0u ||
        native_capture_driver.capture_tick <
            native_capture_driver.dispatch_tick) return FALSE;
    size = snprintf(
        json, sizeof(json),
        "{\"schema\":3,"
        "\"protocol\":\"miel-vliegt-native-dispatch-driver-receipt\","
        "\"status\":\"PASS\","
        "\"driver\":\"%s\","
        "\"bootstrap\":{"
        "\"profile\":\"NATIVE_DISPATCH_DRIVER_V2\","
        "\"profileSha256\":\""
            NATIVE_CAPTURE_DRIVER_BOOTSTRAP_PROFILE_SHA256 "\","
        "\"scenarioSha256\":\""
            NATIVE_CAPTURE_DRIVER_SCENARIO_SHA256 "\","
        "\"initialUserSha256\":\""
            NATIVE_CAPTURE_DRIVER_INITIAL_USER_SHA256 "\"},"
        "\"targetSha256\":\"%s\","
        "\"naturalTransitionEvidence\":false,"
        "\"nativeProcessId\":%lu,\"captureSessionId\":\"%s\","
        "\"managerAddress\":%lu,"
        "\"entryPath\":\"%s\","
        "\"sourceMode\":\"%s\","
        "\"targetMode\":\"%s\","
        "\"ticks\":{\"loginDispatched\":%lu,\"capture\":%lu},"
        "\"semanticStateWritePolicy\":{"
        "\"policy\":\"NO_DIRECT_SEMANTIC_STATE_WRITES\","
        "\"loginUiBootstrapException\":true,\"mission\":false,"
        "\"selector\":false,\"root\":false,"
        "\"projectedValues\":false}}\r\n",
        driver_name,
        native_dispatch_capture_target.target_sha256,
        (unsigned long)GetCurrentProcessId(), capture_session_id,
        (unsigned long)native_capture_driver.manager_address,
        entry_path, source_mode, target_mode,
        (unsigned long)native_capture_driver.dispatch_tick,
        (unsigned long)native_capture_driver.capture_tick);
    if (size <= 0 || (size_t)size >= sizeof(json)) return FALSE;
    file = CreateFileA(
        native_capture_driver_receipt_path, GENERIC_WRITE, 0, NULL,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    if (!WriteFile(file, json, (DWORD)size, &written, NULL) ||
        written != (DWORD)size || !FlushFileBuffers(file)) {
        CloseHandle(file);
        DeleteFileA(native_capture_driver_receipt_path);
        return FALSE;
    }
    return CloseHandle(file);
}

static BOOL native_capture_driver_complete(void)
{
    LONG state = InterlockedCompareExchange(
        &native_capture_driver_state, 0, 0);
    DWORD current = 0u, pending = 0u, application = 0u;
    if (state == NATIVE_CAPTURE_DRIVER_DISABLED) return TRUE;
    if (native_dispatch_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_BOOTSTRAP_TRAVERSAL_V1 ||
        native_dispatch_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_MISSION_BARN_TRAVERSAL_V1) {
        if (state != NATIVE_CAPTURE_DRIVER_WAIT_FLIGHT_READY ||
            native_capture_driver.manager_address == 0u ||
            native_capture_driver.dispatch_thread_id != GetCurrentThreadId() ||
            (DWORD)InterlockedCompareExchange(&engine_thread_id, 0, 0) !=
                GetCurrentThreadId() ||
            session_state != SESSION_DISPATCHED ||
            (native_dispatch_capture_target.capture_driver ==
                MVDS_CAPTURE_DRIVER_BOOTSTRAP_TRAVERSAL_V1
                ? !mvds_mygghanget_absence_completed()
                : !mvds_capture_event_completed())) {
            native_capture_driver_fail(
                "native_capture_driver_completion_contract");
            return FALSE;
        }
        native_capture_driver.capture_tick =
            (DWORD)InterlockedCompareExchange(&manager_tick_count, 0, 0);
        if (!write_native_capture_traversal_receipt()) {
            native_capture_driver_fail(
                "native_capture_driver_receipt_contract");
            return FALSE;
        }
        InterlockedExchange(
            &native_capture_driver_state, NATIVE_CAPTURE_DRIVER_COMPLETE);
        return TRUE;
    }
    if ((state != NATIVE_CAPTURE_DRIVER_WAIT_ACTIVATION &&
         state != NATIVE_CAPTURE_DRIVER_WAIT_CAPTURE) ||
        (native_dispatch_capture_target.capture_driver !=
            MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2 &&
         native_dispatch_capture_target.capture_driver !=
            MVDS_CAPTURE_DRIVER_MISSION_LOCATION_ENTER_V1) ||
        native_capture_driver.dispatch_thread_id != GetCurrentThreadId() ||
        (DWORD)InterlockedCompareExchange(&engine_thread_id, 0, 0) !=
            GetCurrentThreadId() ||
        !canonical_session_root(
            native_capture_driver.manager_address, &application) ||
        !read_pointer(native_capture_driver.manager_address, 0x18cu, &current) ||
        !read_pointer(native_capture_driver.manager_address, 0x190u, &pending) ||
        current != native_capture_driver.target_address || pending != 0u ||
        !body_mode_is_loaded_and_opened(current) ||
        (native_dispatch_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2
         ? (!mvds_completed_generic_readback(
                &native_capture_driver.hook_readback) ||
            native_capture_driver.hook_readback.state == 3)
         : (!mvds_capture_event_completed() ||
            !mvds_read_final_mission_state(
                &native_capture_driver.hook_readback)))) {
        native_capture_driver_fail("native_capture_driver_completion_contract");
        return FALSE;
    }
    (void)application;
    native_capture_driver.capture_tick = (DWORD)InterlockedCompareExchange(
        &manager_tick_count, 0, 0);
    if (state == NATIVE_CAPTURE_DRIVER_WAIT_ACTIVATION) {
        native_capture_driver.activation_tick =
            native_capture_driver.capture_tick;
    }
    if (!write_native_capture_driver_receipt()) {
        native_capture_driver_fail("native_capture_driver_receipt_contract");
        return FALSE;
    }
    InterlockedExchange(
        &native_capture_driver_state, NATIVE_CAPTURE_DRIVER_COMPLETE);
    return TRUE;
}

static void dispatch_native_capture_driver_on_manager_tick(
    DWORD manager_address)
{
    LONG state = InterlockedCompareExchange(
        &native_capture_driver_state, 0, 0);
    DWORD current = 0u, pending = 0u, application = 0u;
    DWORD target_address;
    DWORD tick = (DWORD)InterlockedCompareExchange(&manager_tick_count, 0, 0);
    const char *target_mode = native_dispatch_capture_target.driver_mode;
    const char *current_mode;
    ModeTransitionObservation *barn_transition = &mode_transitions[1];
    void *callback_object = NULL;
    EngineCommandFunction callback = NULL;
    if (state == NATIVE_CAPTURE_DRIVER_DISABLED ||
        state == NATIVE_CAPTURE_DRIVER_COMPLETE ||
        state == NATIVE_CAPTURE_DRIVER_FAILED) return;
    if (state < NATIVE_CAPTURE_DRIVER_WAIT_FLIGHT_READY ||
        state > NATIVE_CAPTURE_DRIVER_WAIT_CAPTURE ||
        state == NATIVE_CAPTURE_DRIVER_IN_CALLBACK) {
        native_capture_driver_fail("native_capture_driver_state_contract");
        return;
    }
    if (native_capture_driver.wait_start_tick == 0u)
        native_capture_driver.wait_start_tick = tick;
    if ((state == NATIVE_CAPTURE_DRIVER_WAIT_FLIGHT_READY &&
         tick - native_capture_driver.wait_start_tick > SESSION_GATE_LIMIT) ||
        (state != NATIVE_CAPTURE_DRIVER_WAIT_FLIGHT_READY &&
         tick - native_capture_driver.dispatch_tick > 3000u)) {
        native_capture_driver_fail("native_capture_driver_timeout_contract");
        return;
    }
    if (state != NATIVE_CAPTURE_DRIVER_WAIT_FLIGHT_READY &&
        (native_capture_driver.manager_address != manager_address ||
         native_capture_driver.dispatch_thread_id != GetCurrentThreadId() ||
         (DWORD)InterlockedCompareExchange(&engine_thread_id, 0, 0) !=
            GetCurrentThreadId())) {
        native_capture_driver_fail("native_capture_driver_thread_contract");
        return;
    }
    if (native_dispatch_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_BOOTSTRAP_TRAVERSAL_V1 ||
        native_dispatch_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_MISSION_BARN_TRAVERSAL_V1) {
        /* The traversal cohorts only own login; the original input-driven
         * barn (-> mygghanget) bootstrap then reaches the target hook, and
         * completion is validated on the producer's capture completion. */
        if (state != NATIVE_CAPTURE_DRIVER_WAIT_FLIGHT_READY) {
            native_capture_driver_fail("native_capture_driver_state_contract");
            return;
        }
        if (!dispatch_native_capture_login_on_manager_tick(manager_address))
            return;
        if (native_capture_driver.manager_address == 0u) {
            native_capture_driver.manager_address = manager_address;
            native_capture_driver.dispatch_thread_id = GetCurrentThreadId();
            native_capture_driver.dispatch_tick = tick;
        } else if (native_capture_driver.manager_address != manager_address ||
                   native_capture_driver.dispatch_thread_id !=
                       GetCurrentThreadId()) {
            native_capture_driver_fail("native_capture_driver_thread_contract");
        }
        return;
    }
    if (state == NATIVE_CAPTURE_DRIVER_WAIT_FLIGHT_READY &&
        !dispatch_native_capture_login_on_manager_tick(manager_address)) {
        return;
    }
    if (state == NATIVE_CAPTURE_DRIVER_WAIT_ACTIVATION) {
        if (!read_pointer(manager_address, 0x18cu, &current) ||
            !read_pointer(manager_address, 0x190u, &pending)) {
            native_capture_driver_fail("native_capture_driver_activation_read");
        } else if (current == native_capture_driver.target_address &&
                   pending == 0u) {
            if (!body_mode_is_loaded_and_opened(current)) {
                native_capture_driver_fail(
                    "native_capture_driver_activation_contract");
                return;
            }
            native_capture_driver.activation_tick = tick;
            InterlockedExchange(&native_capture_driver_state,
                                NATIVE_CAPTURE_DRIVER_WAIT_CAPTURE);
        } else if (current != native_capture_driver.pre_current ||
                   pending != native_capture_driver.target_address) {
            native_capture_driver_fail(
                "native_capture_driver_transition_contract");
        }
        return;
    }
    if (state == NATIVE_CAPTURE_DRIVER_WAIT_CAPTURE) {
        if (!read_pointer(manager_address, 0x18cu, &current) ||
            !read_pointer(manager_address, 0x190u, &pending) ||
            current != native_capture_driver.target_address || pending != 0u ||
            !body_mode_is_loaded_and_opened(current)) {
            native_capture_driver_fail("native_capture_driver_capture_wait");
        }
        return;
    }
    if (session_state != SESSION_DISPATCHED ||
        InterlockedCompareExchange(&login_activation_observed, 0, 0) != 1 ||
        barn_transition->id != 1u || barn_transition->state != 3 ||
        !barn_transition->requested_mode_valid ||
        strcmp(barn_transition->requested_mode, "mode_barn") != 0 ||
        !exact_session_ready(manager_address)) return;
    if (!target_mode || !canonical_session_root(manager_address, &application) ||
        !read_pointer(manager_address, 0x18cu, &current) || current == 0u ||
        !read_pointer(manager_address, 0x190u, &pending) || pending != 0u ||
        !mvds_read_final_mission_state(
            &native_capture_driver.before_readback) ||
        (native_dispatch_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2 &&
         native_capture_driver.before_readback.state == 3)) {
        native_capture_driver_fail("native_capture_driver_precondition_contract");
        return;
    }
    current_mode = mode_name_for_object(current);
    if (!current_mode || strcmp(current_mode, "mode_fly") != 0) {
        native_capture_driver_fail(
            "native_capture_driver_flight_prerequisite_contract");
        return;
    }
    if (!exact_mygghanget_departure_transition(
            manager_address, &native_capture_driver.departure_caller_site) ||
        flight_activation_seed_applied || flight_activation_rng_open ||
        flight_activation_clock_open) {
        native_capture_driver_fail(
            "native_capture_driver_flight_completion_contract");
        return;
    }
    native_capture_driver.flight_ready_tick = tick;
    target_address = (DWORD)(ULONG_PTR)(
        (ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
            (void *)(ULONG_PTR)manager_address, target_mode);
    if (target_address == 0u || target_address == current ||
        !resolve_registered_engine_mode_callback(
            application, manager_address, &callback_object, &callback)) {
        native_capture_driver_fail("native_capture_driver_registry_contract");
        return;
    }
    native_capture_driver.manager_address = manager_address;
    native_capture_driver.target_address = target_address;
    native_capture_driver.pre_current = current;
    native_capture_driver.dispatch_thread_id = GetCurrentThreadId();
    native_capture_driver.dispatch_tick = tick;
    InterlockedExchange(&native_capture_driver_state,
                        NATIVE_CAPTURE_DRIVER_IN_CALLBACK);
    callback(callback_object, ENGINE_MODE_COMMAND_ID, target_mode);
    if (!read_pointer(manager_address, 0x18cu,
                      &native_capture_driver.post_current) ||
        !read_pointer(manager_address, 0x190u,
                      &native_capture_driver.post_pending) ||
        native_capture_driver.post_current != current ||
        native_capture_driver.post_pending != target_address) {
        native_capture_driver_fail("native_capture_driver_postcondition_contract");
        return;
    }
    InterlockedExchange(&native_capture_driver_state,
                        NATIVE_CAPTURE_DRIVER_WAIT_ACTIVATION);
}

static BOOL dispatch_ci_session(DWORD manager_address)
{
    DWORD current = 0u, pending = 0u, application = 0u;
    DWORD login_manager = 0u, login_application = 0u;
    BYTE loaded = 0u, opened = 0u, initialized = 0u;
    void *login = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
        (void *)(ULONG_PTR)manager_address, "mode_login");
    static const char ci_name[] = "MVO_CI";
    BYTE editing = 1u;
    DWORD input_length = (DWORD)(sizeof(ci_name) - 1u);
    if (!login ||
        !read_pointer(manager_address, 0x18cu, &current) ||
        !read_pointer(manager_address, 0x190u, &pending) ||
        !canonical_session_root(manager_address, &application) ||
        current != (DWORD)(ULONG_PTR)login || pending != 0u ||
        !read_byte(current, 0x14u, &loaded) || loaded != 1u ||
        !read_byte(current, 0x15u, &opened) || opened != 1u ||
        !read_byte(current, 0x1f4u, &initialized) || initialized != 1u ||
        !read_pointer(current, 0x48u, &login_manager) ||
        !read_pointer(current, 0x4u, &login_application) ||
        login_manager != manager_address || login_application != application ||
        !canonical_profile_state(application, current)) return FALSE;
    if (!copy_writable((void *)(ULONG_PTR)(current + 0xd5u), ci_name,
                       sizeof(ci_name))) return FALSE;
    if (!copy_writable((void *)(ULONG_PTR)(current + 0x1d8u), &input_length,
                       sizeof(input_length))) return FALSE;
    MemoryBarrier();
    return copy_writable((void *)(ULONG_PTR)(current + 0xd4u), &editing,
                         sizeof(editing));
}

static BOOL login_dispatch_ready(DWORD manager_address)
{
    DWORD current = 0u, pending = 0u, application = 0u;
    DWORD login_manager = 0u, login_application = 0u;
    BYTE loaded = 0u, opened = 0u, initialized = 0u;
    void *login = ((ModeResolveFunction)(ULONG_PTR)MODE_RESOLVE)(
        (void *)(ULONG_PTR)manager_address, "mode_login");
    return login != NULL &&
        read_pointer(manager_address, 0x18cu, &current) &&
        read_pointer(manager_address, 0x190u, &pending) &&
        canonical_session_root(manager_address, &application) &&
        current == (DWORD)(ULONG_PTR)login && pending == 0u &&
        read_byte(current, 0x14u, &loaded) && loaded == 1u &&
        read_byte(current, 0x15u, &opened) && opened == 1u &&
        read_byte(current, 0x1f4u, &initialized) && initialized == 1u &&
        read_pointer(current, 0x48u, &login_manager) &&
        read_pointer(current, 0x4u, &login_application) &&
        login_manager == manager_address && login_application == application &&
        canonical_profile_state(application, current);
}

static BOOL native_capture_driver_owns_navigation(void)
{
    LONG state = InterlockedCompareExchange(
        &native_capture_driver_state, 0, 0);
    return state != NATIVE_CAPTURE_DRIVER_DISABLED;
}

static BOOL native_capture_driver_needs_flight_bootstrap(void)
{
    return InterlockedCompareExchange(
        &native_capture_driver_state, 0, 0) ==
            NATIVE_CAPTURE_DRIVER_WAIT_FLIGHT_READY &&
        session_state == SESSION_DISPATCHED;
}

static BOOL dispatch_native_capture_login_on_manager_tick(
    DWORD manager_address)
{
    if (session_state == SESSION_DISPATCHED) return TRUE;
    if (session_state != SESSION_WAIT_LOGIN) {
        native_capture_driver_fail("native_capture_driver_login_state");
        return FALSE;
    }
    if (mode_transition_number == 0u &&
        !record_bootstrap_pending_login(manager_address)) {
        DWORD current = 0u;
        if (!read_pointer(manager_address, 0x18cu, &current) || current != 0u) {
            native_capture_driver_fail(
                "native_capture_driver_login_pending_missed");
        }
        return FALSE;
    }
    if (++session_gate_count > SESSION_GATE_LIMIT) {
        native_capture_driver_fail("native_capture_driver_login_gate_limit");
        return FALSE;
    }
    if (!login_dispatch_ready(manager_address)) return FALSE;
    if (!dispatch_ci_session(manager_address)) {
        native_capture_driver_fail("native_capture_driver_login_dispatch");
        return FALSE;
    }
    session_state = SESSION_DISPATCHED;
    session_gate_count = 0u;
    emit_session("dispatched", "native_dispatch_driver_login_fsm");
    if (!send_login_submit_input()) {
        native_capture_driver_fail("native_capture_driver_login_submit_input");
        return FALSE;
    }
    return TRUE;
}

static void __attribute__((used)) record_mode_lifecycle(DWORD manager_address)
{
    DWORD last_error = GetLastError();
    correlate_mode_activation(manager_address);
    if (native_capture_driver_owns_navigation() &&
        !native_capture_driver_needs_flight_bootstrap()) {
        /* The fixed driver owns login and final target dispatch.  Between
         * those boundaries it deliberately reuses the original input-driven
         * barn -> mygghanget -> flight bootstrap below, because location
         * loaders consume state owned by a fully activated mode_fly. */
        SetLastError(last_error);
        return;
    }
    if (body_dispatch_state != BODY_DISPATCH_DISABLED &&
        session_state == SESSION_DISPATCHED) {
        /* BODY_ONLY owns navigation after the natural login -> barn edge. */
        SetLastError(last_error);
        return;
    }
    if (session_state == SESSION_WAIT_LOGIN) {
        if (mode_transition_number == 0u &&
            !record_bootstrap_pending_login(manager_address)) {
            DWORD current = 0u;
            if (!read_pointer(manager_address, 0x18cu, &current) ||
                current != 0u) {
                session_fail("bootstrap_login_pending_missed");
            }
            SetLastError(last_error);
            return;
        }
        if (++session_gate_count > SESSION_GATE_LIMIT) {
            session_fail("login_gate_limit");
        } else {
            if (login_dispatch_ready(manager_address)) {
                if (!dispatch_ci_session(manager_address)) {
                    session_fail("login_dispatch");
                } else {
                    session_state = SESSION_DISPATCHED;
                    session_gate_count = 0u;
                    emit_session("dispatched", "native_login_fsm");
                    if (!send_login_submit_input()) {
                        session_fail("login_submit_input");
                    }
                }
            }
        }
    } else if (session_state == SESSION_DISPATCHED) {
        DWORD barn_view = 0u;
        if (!barn_flight_input_sent &&
            exact_barn_ready(manager_address, &barn_view)) {
            if (barn_view != 0u && !barn_door_input_sent) {
                if (!send_projector_click(104, 164)) {
                    session_fail("barn_door_input");
                    SetLastError(last_error);
                    return;
                }
                barn_door_input_sent = TRUE;
                session_gate_count = 0u;
                emit_session("navigating", "native_barn_inside_door");
            } else if (barn_view == 0u) {
                if (!barn_airplane_is_complete(manager_address)) {
                    if (++session_gate_count > SESSION_GATE_LIMIT) {
                        session_fail("barn_airplane_complete_limit");
                    }
                    SetLastError(last_error);
                    return;
                }
                if (!send_barn_escape_input()) {
                    session_fail("barn_escape_input");
                    SetLastError(last_error);
                    return;
                }
                barn_flight_input_sent = TRUE;
                flight_bootstrap_phase =
                    BOOTSTRAP_WAIT_MYGGHANGET_STATE_FIVE;
                session_gate_count = 0u;
                emit_session("navigating", "native_barn_escape_input");
                if (bootstrap_diagnostics_enabled) {
                    emit_bootstrap_diagnostic();
                }
            }
        } else if (barn_flight_input_sent &&
                   observe_native_flight_bootstrap(manager_address) &&
                   exact_session_ready(manager_address)) {
            if (native_capture_driver_needs_flight_bootstrap()) {
                emit_session(
                    "navigating", "native_dispatch_driver_flight_ready");
                SetLastError(last_error);
                return;
            }
            if (!install_manager_render_interposition()) {
                session_fail("manager_render_interposition");
                SetLastError(last_error);
                return;
            }
            if (!send_replay_keys(0u, replay_ticks[0].keys,
                                  replay_ticks[0].focus_active != 0u)) {
                session_fail("windows_input_initialization");
                SetLastError(last_error);
                return;
            }
            if (InterlockedCompareExchange(
                    &session_state, SESSION_ARMED, SESSION_DISPATCHED) !=
                SESSION_DISPATCHED) {
                session_fail("native_preroll_arm_transition");
                SetLastError(last_error);
                return;
            }
            session_gate_count = 0u;
            emit_session("armed", "native_flight_preroll_pending");
        } else {
            ++session_gate_count;
            if (bootstrap_diagnostics_enabled &&
                session_gate_count % 10u == 0u) {
                emit_bootstrap_diagnostic();
            }
            if (session_gate_count > SESSION_GATE_LIMIT) {
                session_fail("flight_readiness_limit");
            }
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) record_login_tick(DWORD login_address)
{
    DWORD manager = 0u;
    DWORD last_error = GetLastError();
    if (read_pointer(login_address, 0x48u, &manager) && manager != 0u) {
        record_mode_lifecycle(manager);
    }
    SetLastError(last_error);
}

static void emit_tick(DWORD tick, DWORD frame, DWORD dt_f32_bits)
{
    char line[TRACE_LINE_SIZE];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"behavior\",\"sequence\":%lu,"
        "\"channel\":\"flight.tick\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"dt_f32_bits\":\"0x%08lx\"},"
        "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, (unsigned long)tick, (unsigned long)frame,
        (unsigned long)dt_f32_bits, (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_clock(DWORD tick, DWORD observed_dt, DWORD scripted_dt)
{
    char line[384];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"clock\",\"sequence\":%lu,"
        "\"channel\":\"clock.tick\",\"tick\":%lu,\"values\":{"
        "\"scripted_dt_f32_bits\":\"0x%08lx\","
        "\"source\":\"scenario_transcript\"},"
        "\"diagnostics\":{\"thread_id\":%lu,"
        "\"observed_dt_f32_bits\":\"0x%08lx\"}}\r\n",
        (unsigned long)sequence, (unsigned long)tick,
        (unsigned long)scripted_dt, (unsigned long)GetCurrentThreadId(),
        (unsigned long)observed_dt);
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_controls(const char *phase, DWORD tick, DWORD frame,
                          DWORD sample, DWORD dt_f32_bits,
                          const BYTE input[16],
                          const FlightObservation *flight, BOOL valid)
{
    char line[TRACE_LINE_SIZE];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"behavior\",\"sequence\":%lu,"
        "\"channel\":\"controls.%s\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"sample\":%lu,\"dt_f32_bits\":\"0x%08lx\","
        "\"keys\":{\"left\":%u,\"right\":%u,\"up\":%u,\"down\":%u,"
        "\"shift\":%u,\"control\":%u},"
        "\"analog_horizontal_f32_bits\":\"0x%08lx\","
        "\"analog_vertical_f32_bits\":\"0x%08lx\","
        "\"input_source\":\"%s\",\"focus_active\":%s,"
        "\"flight_valid\":%s,"
        "\"propulsion_f32_bits\":\"0x%08lx\","
        "\"propulsion_scale_f32_bits\":\"0x%08lx\","
        "\"horizontal_f32_bits\":\"0x%08lx\","
        "\"vertical_f32_bits\":\"0x%08lx\",\"controls_enabled\":%u},"
        "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, phase, (unsigned long)tick,
        (unsigned long)frame, (unsigned long)sample,
        (unsigned long)dt_f32_bits,
        (unsigned int)(input[0] != 0u), (unsigned int)(input[1] != 0u),
        (unsigned int)(input[2] != 0u), (unsigned int)(input[3] != 0u),
        (unsigned int)(input[4] != 0u), (unsigned int)(input[5] != 0u),
        (unsigned long)read_u32(input, 8u),
        (unsigned long)read_u32(input, 12u),
        input_injected ? "windows_sendinput_directinput" : "native_directinput",
        os_input_target_focus ? "true" : "false",
        valid ? "true" : "false",
        (unsigned long)(valid ? flight->propulsion : 0u),
        (unsigned long)(valid ? flight->propulsion_scale : 0u),
        (unsigned long)(valid ? flight->horizontal_control : 0u),
        (unsigned long)(valid ? flight->vertical_control : 0u),
        (unsigned int)(valid ? flight->controls_enabled : 0u),
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_flight_state(const char *channel, const char *phase,
                              DWORD tick, DWORD frame, DWORD call,
                              DWORD depth, DWORD dt_f32_bits, BOOL outer,
                              const FlightObservation *state, BOOL valid)
{
    char line[TRACE_LINE_SIZE];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"behavior\",\"sequence\":%lu,"
        "\"channel\":\"%s\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"phase\":\"%s\",\"call\":%lu,\"depth\":%lu,"
        "\"outer\":%s,\"dt_f32_bits\":\"0x%08lx\",\"state_valid\":%s,"
        "\"position_f32_bits\":[\"0x%08lx\",\"0x%08lx\",\"0x%08lx\"],"
        "\"orientation_wxyz_f32_bits\":[\"0x%08lx\",\"0x%08lx\","
        "\"0x%08lx\",\"0x%08lx\"],"
        "\"velocity_f32_bits\":[\"0x%08lx\",\"0x%08lx\",\"0x%08lx\"],"
        "\"angular_velocity_f32_bits\":[\"0x%08lx\",\"0x%08lx\","
        "\"0x%08lx\"],\"fuel_f32_bits\":\"0x%08lx\","
        "\"integrity_f32_bits\":\"0x%08lx\","
        "\"maximum_integrity_f32_bits\":\"0x%08lx\","
        "\"pending_damage_f32_bits\":\"0x%08lx\","
        "\"damage_gate_timer_f32_bits\":\"0x%08lx\","
        "\"active\":%u,\"inactive\":%u,\"floor_enabled\":%u},"
        "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, channel, (unsigned long)tick,
        (unsigned long)frame, phase, (unsigned long)call,
        (unsigned long)depth, outer ? "true" : "false",
        (unsigned long)dt_f32_bits, valid ? "true" : "false",
        (unsigned long)(valid ? state->position[0] : 0u),
        (unsigned long)(valid ? state->position[1] : 0u),
        (unsigned long)(valid ? state->position[2] : 0u),
        (unsigned long)(valid ? state->orientation_wxyz[0] : 0u),
        (unsigned long)(valid ? state->orientation_wxyz[1] : 0u),
        (unsigned long)(valid ? state->orientation_wxyz[2] : 0u),
        (unsigned long)(valid ? state->orientation_wxyz[3] : 0u),
        (unsigned long)(valid ? state->velocity[0] : 0u),
        (unsigned long)(valid ? state->velocity[1] : 0u),
        (unsigned long)(valid ? state->velocity[2] : 0u),
        (unsigned long)(valid ? state->angular_velocity[0] : 0u),
        (unsigned long)(valid ? state->angular_velocity[1] : 0u),
        (unsigned long)(valid ? state->angular_velocity[2] : 0u),
        (unsigned long)(valid ? state->fuel : 0u),
        (unsigned long)(valid ? state->integrity : 0u),
        (unsigned long)(valid ? state->maximum_integrity : 0u),
        (unsigned long)(valid ? state->pending_damage : 0u),
        (unsigned long)(valid ? state->damage_gate_timer : 0u),
        (unsigned int)(valid ? state->active : 0u),
        (unsigned int)(valid ? state->inactive : 0u),
        (unsigned int)(valid ? state->floor_enabled : 0u),
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static DWORD __attribute__((used)) record_tick(DWORD manager_node,
                                                DWORD dt_f32_bits)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    DWORD effective_dt = dt_f32_bits;
    InterlockedCompareExchange(
        &engine_thread_id, (LONG)GetCurrentThreadId(), 0);
    input_injected = os_input_initialized;
    if (session_state == SESSION_ARMED) {
        if (!flight_activation_seed_applied) {
            session_fail("flight_activation_seed_missing");
        } else if (!close_flight_activation_rng()) {
            session_fail("flight_activation_rng_completion_contract");
        } else if (!close_flight_activation_clock()) {
            session_fail("flight_activation_clock_completion_contract");
        } else if (!prepare_runtime_initial_state(manager_node)) {
            session_fail(replay_runtime_state_bound
                ? "runtime_initial_state_readback_contract"
                : "runtime_initial_state_calibration_contract");
        }
    }
    if (session_state == SESSION_ARMED) {
        original_srand((unsigned int)replay_rng_seed);
        InterlockedExchange(&particle_activation_epoch_open, 0);
        rng_seed_count = 2u;
        rng_draw_count = 0u;
        replay_active_tick = INVALID_ID;
        emit_rng("seed", 1u, replay_rng_seed, NULL);
        InterlockedExchange(&session_state, SESSION_READY);
        emit_session("ready", "seeded_before_first_native_flight_step");
        if (!context) session_fail("seeded_manager_thread_context");
    }
    if (context && session_state == SESSION_READY) {
        ReplayTick *tick;
        if (InterlockedCompareExchange(
                &replay_focus_scheduler_state, 0, 0) == 2 &&
            WaitForSingleObject(
                replay_focus_applied_event,
                FOCUS_TIMELINE_ARM_WAIT_MS) != WAIT_OBJECT_0) {
            session_fail("focus_timeline_manager_resume_order");
        }
        if (session_state != SESSION_READY) {
            SetLastError(last_error);
            return effective_dt;
        }
        if (replay_next_tick >= replay_tick_count) {
            session_fail("replay_tick_overrun");
        } else {
            tick = &replay_ticks[replay_next_tick];
            replay_active_tick = tick->tick;
            replay_active_dt = tick->dt_f32_bits;
            replay_active_keys = tick->keys;
            context->tick = replay_active_tick;
            if (post_natural_edge_input_is_suspended()) {
                if (!suspend_post_natural_edge_input_contract(tick->tick)) {
                    session_fail(
                        "post_natural_edge_input_suspension_contract");
                } else {
                    replay_active_keys = 0u;
                    effective_dt = replay_active_dt;
                    emit_clock(context->tick, dt_f32_bits, effective_dt);
                    ++replay_next_tick;
                }
            } else {
                /* Force released keys to zero in the game's keyboard buffer
                 * before verification so both the verify check and game logic
                 * see the correct state even when SendInput KEYUP is lost in
                 * FEX-emu/Wine's input queue. */
                force_release_lag_keys(manager_node);
                if (!verify_replay_key_sample(manager_node, tick)) {
                    session_fail("directinput_sample_mismatch");
                } else {
                    effective_dt = replay_active_dt;
                    emit_clock(context->tick, dt_f32_bits, effective_dt);
                    ++replay_next_tick;
                }
            }
        }
        context->tick_dt_f32_bits = effective_dt;
        context->controls_sample = INVALID_ID;
        context->collision_sample = INVALID_ID;
        emit_tick(context->tick, current_frame(), effective_dt);
    }
    SetLastError(last_error);
    return effective_dt;
}

static void __attribute__((used)) record_controls_pre(DWORD mode_address,
                                                       DWORD dt_f32_bits)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    BYTE input[16] = {0};
    DWORD flight_address = 0u;
    FlightObservation flight = {0};
    BOOL valid = FALSE;
    if (context && session_state == SESSION_READY &&
        !post_natural_edge_input_is_suspended()) {
        context->controls_sample = next_id(&controls_number);
        context->controls_dt_f32_bits = dt_f32_bits;
        if (!calibration_observation_only) {
            copy_readable((const void *)(ULONG_PTR)(mode_address + 0x70u),
                          input, sizeof(input));
            if (read_pointer(mode_address, 0x4cu, &flight_address)) {
                valid = capture_flight(flight_address, &flight);
            }
            emit_controls("pre", context->tick, current_frame(),
                          context->controls_sample, dt_f32_bits,
                          input, &flight, valid);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) record_controls_post(DWORD mode_address)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    BYTE input[16] = {0};
    DWORD flight_address = 0u;
    FlightObservation flight = {0};
    BOOL valid = FALSE;
    if (context && session_state == SESSION_READY &&
        !post_natural_edge_input_is_suspended() &&
        context->controls_sample != INVALID_ID) {
        if (!calibration_observation_only) {
            copy_readable((const void *)(ULONG_PTR)(mode_address + 0x70u),
                          input, sizeof(input));
            if (read_pointer(mode_address, 0x4cu, &flight_address)) {
                valid = capture_flight(flight_address, &flight);
            }
            emit_controls(
                "post", context->tick, current_frame(),
                context->controls_sample, context->controls_dt_f32_bits,
                input, &flight, valid);
        }
        context->controls_sample = INVALID_ID;
        if (replay_active_tick != INVALID_ID &&
            replay_next_tick < replay_tick_count &&
            os_input_target_tick == replay_active_tick) {
            ReplayTick *next_tick = &replay_ticks[replay_next_tick];
            BOOL focus_changes =
                os_input_target_focus != next_tick->focus_active;
            BOOL transitioned = focus_changes
                ? (!next_tick->focus_active &&
                   arm_replay_focus_timeline(next_tick->tick))
                : send_replay_keys(
                    next_tick->tick, next_tick->keys,
                    next_tick->focus_active != 0u);
            if (!transitioned) {
                session_fail(focus_changes
                    ? "focus_timeline_transition"
                    : "windows_input_transition");
            }
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) record_physics_entry(DWORD flight_address,
                                                        DWORD dt_f32_bits)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    FlightObservation state = {0};
    BOOL valid;
    if (session_state != SESSION_READY) {
        SetLastError(last_error);
        return;
    }
    valid = capture_flight(flight_address, &state);
    if (context) {
        DWORD depth = context->physics_depth++;
        if (depth < PHYSICS_STACK_DEPTH) {
            PhysicsCall *call = &context->physics_stack[depth];
            call->id = next_id(&physics_number);
            call->tick = context->tick;
            call->frame = current_frame();
            call->dt_f32_bits = dt_f32_bits;
            call->flight_address = flight_address;
            emit_flight_state("physics.state", "enter", call->tick,
                              call->frame, call->id, depth, dt_f32_bits,
                              depth == 0u, &state, valid);
        } else {
            ++context->physics_overflow;
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) record_physics_leave(DWORD flight_address)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    if (session_state != SESSION_READY) {
        SetLastError(last_error);
        return;
    }
    if (context && context->physics_depth != 0u) {
        DWORD depth = --context->physics_depth;
        if (depth < PHYSICS_STACK_DEPTH) {
            PhysicsCall call = context->physics_stack[depth];
            FlightObservation state = {0};
            BOOL valid = call.flight_address == flight_address &&
                         capture_flight(flight_address, &state);
            emit_flight_state("physics.state", "leave", call.tick,
                              call.frame, call.id, depth, call.dt_f32_bits,
                              depth == 0u, &state, valid);
        } else if (context->physics_overflow != 0u) {
            --context->physics_overflow;
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) record_collision_entry(DWORD flight_address,
                                                          DWORD dt_f32_bits)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    if (session_state != SESSION_READY) {
        SetLastError(last_error);
        return;
    }
    if (context) {
        FlightObservation state = {0};
        BOOL valid = capture_flight(flight_address, &state);
        context->collision_sample = next_id(&collision_number);
        context->collision_dt_f32_bits = dt_f32_bits;
        emit_flight_state("collision.state", "enter", context->tick,
                          current_frame(), context->collision_sample, 0u,
                          dt_f32_bits, TRUE, &state, valid);
    }
    SetLastError(last_error);
}

static void __attribute__((used)) record_collision_commit(DWORD flight_address)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    if (session_state != SESSION_READY) {
        SetLastError(last_error);
        return;
    }
    if (context && context->collision_sample != INVALID_ID) {
        FlightObservation state = {0};
        BOOL valid = capture_flight(flight_address, &state);
        emit_flight_state("collision.state", "commit", context->tick,
                          current_frame(), context->collision_sample, 0u,
                          context->collision_dt_f32_bits, TRUE, &state, valid);
        context->collision_sample = INVALID_ID;
    }
    SetLastError(last_error);
}

static void emit_outcome_contact(void)
{
    char line[384];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"outcome\",\"sequence\":%lu,"
        "\"channel\":\"outcome.contact\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"kind\":\"correction\"},"
        "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, (unsigned long)replay_active_tick,
        (unsigned long)current_frame(),
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_outcome_damage(DWORD damage, DWORD integrity, BOOL terminal)
{
    char line[512];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"outcome\",\"sequence\":%lu,"
        "\"channel\":\"outcome.damage\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"effective_damage_f32_bits\":\"0x%08lx\","
        "\"integrity_after_f32_bits\":\"0x%08lx\",\"terminal\":%s},"
        "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, (unsigned long)replay_active_tick,
        (unsigned long)current_frame(),
        (unsigned long)damage, (unsigned long)integrity,
        terminal ? "true" : "false", (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_outcome_crash(void)
{
    char line[384];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"outcome\",\"sequence\":%lu,"
        "\"channel\":\"outcome.crash\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"terminal\":true},"
        "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, (unsigned long)replay_active_tick,
        (unsigned long)current_frame(),
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void emit_outcome_terrain(LONG terrain_class)
{
    char line[384];
    DWORD sequence = next_id(&sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"outcome\",\"sequence\":%lu,"
        "\"channel\":\"outcome.terrain\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"class\":%ld},"
        "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, (unsigned long)replay_active_tick,
        (unsigned long)current_frame(),
        (long)terrain_class, (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static void __attribute__((used)) record_fuel(DWORD flight_address,
                                               BOOL depleted)
{
    DWORD last_error = GetLastError();
    DWORD fuel = 0u;
    char line[384];
    DWORD sequence;
    int size;
    if (session_state != SESSION_READY) {
        SetLastError(last_error);
        return;
    }
    if (!read_pointer(flight_address, 0x198u, &fuel)) {
        session_fail("fuel_state");
        SetLastError(last_error);
        return;
    }
    sequence = next_id(&sequence_number);
    size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"system\",\"sequence\":%lu,"
        "\"channel\":\"system.fuel\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"fuel_f32_bits\":\"0x%08lx\",\"depleted\":%s},"
        "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, (unsigned long)replay_active_tick,
        (unsigned long)current_frame(),
        (unsigned long)fuel, depleted ? "true" : "false",
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
    SetLastError(last_error);
}

static void __attribute__((used)) record_contact(DWORD flight_address)
{
    DWORD last_error = GetLastError();
    FlightObservation flight;
    if (session_state != SESSION_READY) {
        SetLastError(last_error);
        return;
    }
    if (!capture_flight(flight_address, &flight)) session_fail("contact_state");
    else emit_outcome_contact();
    SetLastError(last_error);
}

static void __attribute__((used)) record_damage_effective(
    DWORD flight_address, DWORD damage_f32_bits)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    FlightObservation flight;
    if (session_state != SESSION_READY) {
        SetLastError(last_error);
        return;
    }
    if (!context || !capture_flight(flight_address, &flight)) {
        session_fail("damage_effective_state");
    } else {
        context->damage_f32_bits = damage_f32_bits;
        context->damage_integrity_f32_bits = flight.integrity;
        context->damage_terminal = FALSE;
    }
    SetLastError(last_error);
}

static void __attribute__((used)) record_damage_post(DWORD flight_address,
                                                       DWORD damage_f32_bits)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    FlightObservation flight;
    float integrity;
    if (session_state != SESSION_READY) {
        SetLastError(last_error);
        return;
    }
    if (!context || !capture_flight(flight_address, &flight) ||
        context->damage_f32_bits != damage_f32_bits) {
        session_fail("damage_post_state");
    } else {
        memcpy(&integrity, &flight.integrity, sizeof(integrity));
        context->damage_integrity_f32_bits = flight.integrity;
        context->damage_terminal = !(integrity > 0.0f);
        emit_outcome_damage(damage_f32_bits, flight.integrity,
                            context->damage_terminal);
    }
    SetLastError(last_error);
}

static void __attribute__((used)) record_damage_nonterminal(void)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    if (session_state != SESSION_READY) {
        SetLastError(last_error);
        return;
    }
    if (!context || context->damage_terminal) {
        session_fail("damage_branch_mismatch");
    }
    SetLastError(last_error);
}

static void __attribute__((used)) record_terminal_crash(void)
{
    DWORD last_error = GetLastError();
    if (session_state != SESSION_READY) {
        SetLastError(last_error);
        return;
    }
    emit_outcome_crash();
    SetLastError(last_error);
}

static void __attribute__((used)) record_terrain_result(LONG terrain_class)
{
    DWORD last_error = GetLastError();
    if (session_state != SESSION_READY) {
        SetLastError(last_error);
        return;
    }
    /*
     * Terrain-class range check — FEX x87 emulation context.
     *
     * The game's own disassembly tests terrain_class with `cmpl $7` followed
     * by an unsigned JA/JAE branch: it ONLY rejects values above 7.  There is
     * no lower-bound guard, so negative sentinel values (e.g. -1 meaning
     * "no terrain hit") flow through the normal game path unconditionally.
     *
     * Under FEX-emu (x86→ARM translation) the x87 FPU emulation can produce
     * a terrain_class integer that differs slightly from real x86 hardware,
     * occasionally yielding a small negative value that native hardware does
     * not.  The previous `< -1` lower bound here was STRICTER than the game's
     * own check and triggered a false session_fail("terrain_class_range") on
     * the approach-landing scenario — the first scenario to exercise terrain
     * collision code.  That false failure surfaced as exit code 5 because
     * SESSION_FAILED == 5 and the launcher terminates the target with
     * TerminateProcess(hProcess, 5u) on observer-reported failure.
     *
     * We now match the game exactly: reject only values > 7.  Negative values
     * are passed through to emit_outcome_terrain and additionally logged as a
     * diagnostic so future FEX divergences are visible in the trace without
     * aborting the scenario.
     */
    if (terrain_class < 0) {
        char diag[256];
        DWORD sequence = next_id(&sequence_number);
        int size = snprintf(
            diag, sizeof(diag),
            "MVT {\"record\":\"diagnostic\",\"sequence\":%lu,"
            "\"channel\":\"diagnostic.terrain_class\",\"tick\":%lu,"
            "\"frame\":%lu,\"values\":{\"class\":%ld},"
            "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
            (unsigned long)sequence, (unsigned long)replay_active_tick,
            (unsigned long)current_frame(), (long)terrain_class,
            (unsigned long)GetCurrentThreadId());
        if (size > 0 && (size_t)size < sizeof(diag)) append_record(diag, (DWORD)size);
    }
    if (terrain_class > 7) {
        session_fail("terrain_class_range");
    } else {
        emit_outcome_terrain(terrain_class);
    }
    SetLastError(last_error);
}

static void __attribute__((used)) record_camera_commit(DWORD controller_address)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    DWORD camera_address = 0u;
    DWORD flight_address = 0u;
    DWORD location_state = INVALID_ID;
    DWORD camera_offset = 0u, flight_offset = 0u;
    BYTE manual_camera_enabled = 0xffu;
    BYTE move_forward = 0xffu;
    BYTE move_backward = 0xffu;
    const char *camera_control_owner;
    const char *mode_name;
    BYTE render_srt[0x38u] = {0};
    BYTE projection[0x24u] = {0};
    DWORD focal_pixels = 0u;
    FlightObservation flight = {0};
    BOOL camera_valid = FALSE;
    BOOL flight_valid = FALSE;
    char line[TRACE_LINE_SIZE];
    DWORD sequence;
    int size;
    if (session_state != SESSION_READY || !context) {
        SetLastError(last_error);
        return;
    }
    if (camera_checkpoint_tick == context->tick) {
        SetLastError(last_error);
        return;
    }
    camera_checkpoint_tick = context->tick;
    mode_name = mode_name_for_object(controller_address);
    if (mode_name && strcmp(mode_name, "mode_fly") == 0) {
        camera_control_owner = "mode_fly";
        camera_offset = 0x58u;
        flight_offset = 0x64u;
        read_byte(controller_address, 0x494cu, &manual_camera_enabled);
        read_byte(controller_address, 0x494du, &move_forward);
        read_byte(controller_address, 0x494eu, &move_backward);
    } else {
        camera_control_owner = "common_location";
        camera_offset = 0x54u;
        flight_offset = 0x5cu;
        copy_readable((const void *)(ULONG_PTR)(controller_address + 0x8dcu),
                      (BYTE *)&location_state, sizeof(location_state));
    }
    if (read_pointer(controller_address, camera_offset, &camera_address)) {
        camera_valid = copy_readable(
                (const void *)(ULONG_PTR)(camera_address + 0x9a4u),
                render_srt, sizeof(render_srt)) == sizeof(render_srt) &&
            copy_readable(
                (const void *)(ULONG_PTR)(camera_address + 0x928u),
                projection, sizeof(projection)) == sizeof(projection) &&
            copy_readable(
                (const void *)(ULONG_PTR)(camera_address + 0x900u),
                (BYTE *)&focal_pixels, sizeof(focal_pixels)) == sizeof(focal_pixels);
    }
    if (read_pointer(controller_address, flight_offset, &flight_address)) {
        flight_valid = capture_flight(flight_address, &flight);
    }
    sequence = next_id(&sequence_number);
    size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"behavior\",\"sequence\":%lu,"
        "\"channel\":\"camera.commit\",\"tick\":%lu,\"frame\":%lu,"
        "\"values\":{\"camera_valid\":%s,\"flight_valid\":%s,"
        "\"camera_control_owner\":\"%s\","
        "\"location_state\":%lu,"
        "\"manual_camera_enabled\":%u,"
        "\"move_forward\":%u,\"move_backward\":%u,"
        "\"render_world_position_f32_bits\":[\"0x%08lx\",\"0x%08lx\",\"0x%08lx\"],"
        "\"render_scaled_rotation_row_major_f32_bits\":[\"0x%08lx\",\"0x%08lx\","
        "\"0x%08lx\",\"0x%08lx\",\"0x%08lx\",\"0x%08lx\","
        "\"0x%08lx\",\"0x%08lx\",\"0x%08lx\"],"
        "\"render_scale_f32_bits\":\"0x%08lx\","
        "\"render_inverse_scale_squared_f32_bits\":\"0x%08lx\","
        "\"near_f32_bits\":\"0x%08lx\",\"far_f32_bits\":\"0x%08lx\","
        "\"horizontal_fov_degrees_f32_bits\":\"0x%08lx\","
        "\"centre_f32_bits\":[\"0x%08lx\",\"0x%08lx\"],"
        "\"window_endpoints_f32_bits\":[\"0x%08lx\",\"0x%08lx\","
        "\"0x%08lx\",\"0x%08lx\"],"
        "\"focal_pixels_f32_bits\":\"0x%08lx\","
        "\"flight_position_f32_bits\":[\"0x%08lx\",\"0x%08lx\","
        "\"0x%08lx\"]},\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, (unsigned long)context->tick,
        (unsigned long)current_frame(), camera_valid ? "true" : "false",
        flight_valid ? "true" : "false",
        camera_control_owner,
        (unsigned long)location_state,
        (unsigned int)manual_camera_enabled,
        (unsigned int)move_forward,
        (unsigned int)move_backward,
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x2cu) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x30u) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x34u) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x0u) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x4u) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x8u) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0xcu) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x10u) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x14u) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x18u) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x1cu) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x20u) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x24u) : 0u),
        (unsigned long)(camera_valid ? read_u32(render_srt, 0x28u) : 0u),
        (unsigned long)(camera_valid ? read_u32(projection, 0x0u) : 0u),
        (unsigned long)(camera_valid ? read_u32(projection, 0x4u) : 0u),
        (unsigned long)(camera_valid ? read_u32(projection, 0x8u) : 0u),
        (unsigned long)(camera_valid ? read_u32(projection, 0xcu) : 0u),
        (unsigned long)(camera_valid ? read_u32(projection, 0x10u) : 0u),
        (unsigned long)(camera_valid ? read_u32(projection, 0x14u) : 0u),
        (unsigned long)(camera_valid ? read_u32(projection, 0x18u) : 0u),
        (unsigned long)(camera_valid ? read_u32(projection, 0x1cu) : 0u),
        (unsigned long)(camera_valid ? read_u32(projection, 0x20u) : 0u),
        (unsigned long)(camera_valid ? focal_pixels : 0u),
        (unsigned long)(flight_valid ? flight.position[0] : 0u),
        (unsigned long)(flight_valid ? flight.position[1] : 0u),
        (unsigned long)(flight_valid ? flight.position[2] : 0u),
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
    SetLastError(last_error);
}

static void __attribute__((used)) note_camera_source_commit(
    DWORD controller_address)
{
    (void)controller_address;
    if (session_state == SESSION_READY) {
        InterlockedIncrement(&camera_commit_count);
    }
}

static BOOL range_readable(const BYTE *address, DWORD size)
{
    while (size != 0u) {
        MEMORY_BASIC_INFORMATION information;
        SIZE_T available;
        DWORD take;
        if (!VirtualQuery(address, &information, sizeof(information)) ||
            information.State != MEM_COMMIT ||
            (information.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0u) {
            return FALSE;
        }
        available = (SIZE_T)((BYTE *)information.BaseAddress +
                             information.RegionSize - address);
        take = available < size ? (DWORD)available : size;
        if (take == 0u) return FALSE;
        address += take;
        size -= take;
    }
    return TRUE;
}

static BOOL address_executable(DWORD address)
{
    MEMORY_BASIC_INFORMATION information;
    DWORD protection;
    if (address == 0u ||
        !VirtualQuery((const void *)(ULONG_PTR)address, &information,
                      sizeof(information)) ||
        information.State != MEM_COMMIT) return FALSE;
    protection = information.Protect & 0xffu;
    return protection == PAGE_EXECUTE ||
        protection == PAGE_EXECUTE_READ ||
        protection == PAGE_EXECUTE_READWRITE ||
        protection == PAGE_EXECUTE_WRITECOPY;
}

static BOOL write_handle_all(HANDLE file, const BYTE *bytes, DWORD size)
{
    while (size != 0u) {
        DWORD written = 0u;
        if (!WriteFile(file, bytes, size, &written, NULL) || written == 0u) {
            return FALSE;
        }
        bytes += written;
        size -= written;
    }
    return TRUE;
}

static BOOL capture_framebuffer(DWORD device_address, DWORD tick,
                                BYTE raw_digest[32])
{
    DWORD vtable = 0u;
    DWORD virtual_read_screen = 0u;
    HMODULE device_module;
    MEMORY_BASIC_INFORMATION function_information;
    ReadScreenFunction virtual_read;
    void *image = NULL;
    void *pixels;
    BYTE *canonical_pixels = NULL;
    int width, height, pitch, image_size, pixel_size_bits, pixel_size, format;
    DWORD raw_size, native_raw_size, row, column, non_black_pixel_count = 0u;
    DWORD canonical_pitch;
    LONG render_ordinal;
    ProjectorWindowEvidence window_evidence;
    char raw_path[MAX_PATH * 2 + 16] = {0};
    char metadata_path[MAX_PATH * 2 + 16] = {0};
    char native_raw_path[MAX_PATH * 2 + 24] = {0};
    char native_metadata_path[MAX_PATH * 2 + 24] = {0};
    char raw_hash[65];
    char native_raw_hash[65];
    char scenario_hash[65];
    char device_hash[65];
    char config_hash[65];
    char device_path[MAX_PATH * 2];
    char layout_record[512];
    BYTE device_digest[32];
    BYTE config_digest[32];
    BYTE native_raw_digest[32];
    DWORD device_path_size;
    char metadata[1536];
    char native_metadata[1024];
    int metadata_size;
    int native_metadata_size;
    int layout_record_size;
    int raw_path_size;
    int metadata_path_size;
    int native_raw_path_size;
    int native_metadata_path_size;
    HANDLE raw_file = INVALID_HANDLE_VALUE;
    HANDLE metadata_file = INVALID_HANDLE_VALUE;
    HANDLE native_raw_file = INVALID_HANDLE_VALUE;
    HANDLE native_metadata_file = INVALID_HANDLE_VALUE;
    BOOL raw_created = FALSE;
    BOOL metadata_created = FALSE;
    BOOL native_raw_created = FALSE;
    BOOL native_metadata_created = FALSE;
    Sha256Context hash;
    BOOL success = FALSE;
    framebuffer_capture_error = NULL;
    render_ordinal = InterlockedCompareExchange(&manager_render_count, 0, 0);
    if (!inspect_projector_window(&window_evidence) ||
        window_evidence.client_width != PROJECTOR_CLIENT_WIDTH ||
        window_evidence.client_height != PROJECTOR_CLIENT_HEIGHT) {
        framebuffer_capture_error = "framebuffer_window_readiness";
        return FALSE;
    }
    if (render_ordinal <= 0) {
        framebuffer_capture_error = "framebuffer_paint_progress";
        return FALSE;
    }
    if (!read_pointer(device_address, 0u, &vtable)) {
        framebuffer_capture_error = "framebuffer_device_vtable";
        return FALSE;
    }
    if (!read_pointer(vtable, 0xbcu, &virtual_read_screen) ||
        !address_executable(virtual_read_screen)) {
        framebuffer_capture_error = "framebuffer_read_screen_slot";
        return FALSE;
    }
    device_module = GetModuleHandleA("gtSoftware.dll");
    device_path_size = device_module ? GetModuleFileNameA(
        device_module, device_path, sizeof(device_path)) : 0u;
    if (!device_module || device_path_size == 0u ||
        device_path_size >= sizeof(device_path) ||
        !hash_file(device_path, device_digest) ||
        memcmp(device_digest, EXPECTED_GT_SOFTWARE_SHA256,
               sizeof(device_digest)) != 0 ||
        !VirtualQuery((const void *)(ULONG_PTR)virtual_read_screen,
                      &function_information, sizeof(function_information)) ||
        function_information.AllocationBase != device_module) {
        framebuffer_capture_error = "framebuffer_device_module";
        return FALSE;
    }
    if (!hash_file("config.ini", config_digest) ||
        memcmp(config_digest, EXPECTED_CONFIG_SHA256,
               sizeof(config_digest)) != 0) {
        framebuffer_capture_error = "framebuffer_device_config";
        return FALSE;
    }
    virtual_read = (ReadScreenFunction)(ULONG_PTR)virtual_read_screen;
    image = virtual_read((void *)(ULONG_PTR)device_address, NULL);
    if (!image) {
        framebuffer_capture_error = "framebuffer_read_screen_null";
        return FALSE;
    }
    width = image_get_width(image, 0);
    height = image_get_height(image, 0);
    pitch = image_get_pitch(image, 0);
    image_size = image_get_size(image, 0);
    pixel_size_bits = image_get_pixel_size(image);
    format = image_get_format(image);
    pixels = image_get_pointer(image, 0);
    if (width <= 0 || height <= 0 || pitch <= 0 || image_size <= 0 ||
        pixel_size_bits <= 0 || pixel_size_bits > 128 ||
        (pixel_size_bits & 7) != 0 || format < 3 || format > 8 || !pixels ||
        (DWORD)height > FRAME_SIZE_LIMIT / (DWORD)pitch) {
        framebuffer_capture_error = "framebuffer_image_metadata";
        goto cleanup;
    }
    layout_record_size = snprintf(
        layout_record, sizeof(layout_record),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-framebuffer-layout\","
        "\"tick\":%lu,\"width\":%d,\"height\":%d,\"pitch\":%d,"
        "\"image_size\":%d,\"pixel_size_bits\":%d,\"format\":%d,"
        "\"thread_id\":%lu}\r\n",
        (unsigned long)tick, width, height, pitch, image_size,
        pixel_size_bits, format, (unsigned long)GetCurrentThreadId());
    if (layout_record_size <= 0 ||
        (size_t)layout_record_size >= sizeof(layout_record)) {
        framebuffer_capture_error = "framebuffer_layout_diagnostic";
        goto cleanup;
    }
    append_record(layout_record, (DWORD)layout_record_size);
    pixel_size = pixel_size_bits / 8;
    if (!((format == 5 && pixel_size == 2) ||
          (format == 8 && pixel_size == 4))) {
        framebuffer_capture_error = "framebuffer_image_layout";
        goto cleanup;
    }
    if (width != window_evidence.client_width ||
        height != window_evidence.client_height ||
        (DWORD)pitch < (DWORD)width * (DWORD)pixel_size) {
        framebuffer_capture_error = "framebuffer_image_pitch";
        goto cleanup;
    }
    native_raw_size = (DWORD)height * (DWORD)pitch;
    if (native_raw_size > FRAME_SIZE_LIMIT ||
        (DWORD)image_size != native_raw_size ||
        !range_readable((const BYTE *)pixels, native_raw_size)) {
        framebuffer_capture_error = "framebuffer_image_buffer";
        goto cleanup;
    }
    canonical_pitch = (DWORD)width * 4u;
    if ((DWORD)height > FRAME_SIZE_LIMIT / canonical_pitch) {
        framebuffer_capture_error = "framebuffer_canonical_size";
        goto cleanup;
    }
    raw_size = (DWORD)height * canonical_pitch;
    canonical_pixels = HeapAlloc(GetProcessHeap(), 0, raw_size);
    if (!canonical_pixels) {
        framebuffer_capture_error = "framebuffer_canonical_alloc";
        goto cleanup;
    }
    for (row = 0u; row < (DWORD)height; ++row) {
        for (column = 0u; column < (DWORD)width; ++column) {
            const BYTE *source = (const BYTE *)pixels +
                row * (DWORD)pitch + column * (DWORD)pixel_size;
            BYTE *target = canonical_pixels +
                row * canonical_pitch + column * 4u;
            if (format == 5) {
                WORD rgb565 = (WORD)source[0] | ((WORD)source[1] << 8);
                BYTE red5 = (BYTE)((rgb565 >> 11) & 0x1fu);
                BYTE green6 = (BYTE)((rgb565 >> 5) & 0x3fu);
                BYTE blue5 = (BYTE)(rgb565 & 0x1fu);
                target[0] = (BYTE)(((DWORD)blue5 * 255u + 15u) / 31u);
                target[1] = (BYTE)(((DWORD)green6 * 255u + 31u) / 63u);
                target[2] = (BYTE)(((DWORD)red5 * 255u + 15u) / 31u);
                target[3] = 0u;
            } else {
                memcpy(target, source, 4u);
            }
            if (target[0] != 0u || target[1] != 0u ||
                target[2] != 0u) {
                ++non_black_pixel_count;
            }
        }
    }
    if (non_black_pixel_count == 0u) {
        framebuffer_capture_error = "framebuffer_unpainted";
        goto cleanup;
    }
    raw_path_size = snprintf(raw_path, sizeof(raw_path), "%s.raw", frame_prefix);
    metadata_path_size = snprintf(metadata_path, sizeof(metadata_path),
                                  "%s.json", frame_prefix);
    native_raw_path_size = snprintf(
        native_raw_path, sizeof(native_raw_path), "%s.native.raw", frame_prefix);
    native_metadata_path_size = snprintf(
        native_metadata_path, sizeof(native_metadata_path),
        "%s.native.json", frame_prefix);
    if (raw_path_size <= 0 || (size_t)raw_path_size >= sizeof(raw_path) ||
        metadata_path_size <= 0 ||
        (size_t)metadata_path_size >= sizeof(metadata_path) ||
        native_raw_path_size <= 0 ||
        (size_t)native_raw_path_size >= sizeof(native_raw_path) ||
        native_metadata_path_size <= 0 ||
        (size_t)native_metadata_path_size >= sizeof(native_metadata_path)) {
        framebuffer_capture_error = "framebuffer_output_path";
        goto cleanup;
    }
    native_raw_file = CreateFileA(
        native_raw_path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (native_raw_file == INVALID_HANDLE_VALUE) {
        framebuffer_capture_error = "framebuffer_native_raw_create";
        goto cleanup;
    }
    native_raw_created = TRUE;
    sha256_init(&hash);
    sha256_update(&hash, (const BYTE *)pixels, native_raw_size);
    sha256_final(&hash, native_raw_digest);
    if (!write_handle_all(
            native_raw_file, (const BYTE *)pixels, native_raw_size) ||
        !FlushFileBuffers(native_raw_file)) {
        framebuffer_capture_error = "framebuffer_native_raw_write";
        goto cleanup;
    }
    CloseHandle(native_raw_file);
    native_raw_file = INVALID_HANDLE_VALUE;
    raw_file = CreateFileA(raw_path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (raw_file == INVALID_HANDLE_VALUE) {
        framebuffer_capture_error = "framebuffer_raw_create";
        goto cleanup;
    }
    raw_created = TRUE;
    sha256_init(&hash);
    sha256_update(&hash, canonical_pixels, raw_size);
    sha256_final(&hash, raw_digest);
    if (!write_handle_all(raw_file, canonical_pixels, raw_size) ||
        !FlushFileBuffers(raw_file)) {
        framebuffer_capture_error = "framebuffer_raw_write";
        goto cleanup;
    }
    CloseHandle(raw_file);
    raw_file = INVALID_HANDLE_VALUE;
    encode_sha256(raw_digest, raw_hash);
    encode_sha256(native_raw_digest, native_raw_hash);
    encode_sha256(replay_sha256, scenario_hash);
    encode_sha256(device_digest, device_hash);
    encode_sha256(config_digest, config_hash);
    native_metadata_size = snprintf(
        native_metadata, sizeof(native_metadata),
        "{\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-frame-source-layout\","
        "\"scenario\":\"%s\",\"scenario_sha256\":\"%s\","
        "\"tick\":%lu,\"width\":%d,\"height\":%d,\"pitch\":%d,"
        "\"bits_per_pixel\":%d,\"bytes_per_pixel\":%d,"
        "\"gt_format_id\":%d,\"gt_format_name\":\"%s\","
        "\"image_size\":%d,\"raw_size\":%lu,\"raw_sha256\":\"%s\","
        "\"row_layout\":\"native_pitch_bytes\","
        "\"origin\":\"top-left\",\"packed_format\":\"%s\","
        "\"conversion\":\"%s\"}\r\n",
        replay_scenario, scenario_hash, (unsigned long)tick,
        width, height, pitch, pixel_size_bits, pixel_size, format,
        format == 5 ? "RGB565" : "ARGB8888", image_size,
        (unsigned long)native_raw_size, native_raw_hash,
        format == 5 ? "rgb565-le" : "xrgb8888-le",
        format == 5 ? "rgb565-le-to-xrgb8888-le" : "identity");
    if (native_metadata_size <= 0 ||
        (size_t)native_metadata_size >= sizeof(native_metadata)) {
        framebuffer_capture_error = "framebuffer_native_metadata_encoding";
        goto cleanup;
    }
    native_metadata_file = CreateFileA(
        native_metadata_path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (native_metadata_file == INVALID_HANDLE_VALUE) {
        framebuffer_capture_error = "framebuffer_native_metadata_create";
        goto cleanup;
    }
    native_metadata_created = TRUE;
    if (!write_handle_all(
            native_metadata_file, (const BYTE *)native_metadata,
            (DWORD)native_metadata_size) ||
        !FlushFileBuffers(native_metadata_file)) {
        framebuffer_capture_error = "framebuffer_native_metadata_write";
        goto cleanup;
    }
    CloseHandle(native_metadata_file);
    native_metadata_file = INVALID_HANDLE_VALUE;
    metadata_size = snprintf(
        metadata, sizeof(metadata),
        "{\"schema\":2,\"protocol\":\"miel-vliegt-native-frame\","
        "\"scenario\":\"%s\",\"scenario_sha256\":\"%s\","
        "\"tick\":%lu,\"width\":%d,\"height\":%d,\"pitch\":%d,"
        "\"window_role\":\"top-level-projector\","
        "\"window_top_level\":true,\"window_visible\":true,"
        "\"window_enabled\":true,\"window_iconic\":false,"
        "\"client_width\":%ld,\"client_height\":%ld,"
        "\"render_ordinal\":%ld,"
        "\"paint_progress\":\"manager-render-and-non-black\","
        "\"non_black_pixel_count\":%lu,"
        "\"bits_per_pixel\":%d,\"bytes_per_pixel\":%d,"
        "\"gt_format_id\":%d,\"gt_format_name\":\"ARGB8888\","
        "\"image_size\":%d,"
        "\"raw_size\":%lu,\"raw_sha256\":\"%s\","
        "\"row_layout\":\"native_pitch_bytes\","
        "\"origin\":\"top-left\",\"packed_format\":\"xrgb8888-le\","
        "\"memory_byte_order\":\"bgrx\",\"surface_alpha\":\"unused\","
        "\"device_config\":\"config.ini\","
        "\"device_config_sha256\":\"%s\","
        "\"device_module\":\"gtSoftware.dll\","
        "\"device_module_sha256\":\"%s\"}\r\n",
        replay_scenario, scenario_hash, (unsigned long)tick,
        width, height, (int)canonical_pitch,
        (long)window_evidence.client_width,
        (long)window_evidence.client_height, (long)render_ordinal,
        (unsigned long)non_black_pixel_count,
        32, 4, 8, (int)raw_size,
        (unsigned long)raw_size, raw_hash, config_hash, device_hash);
    if (metadata_size <= 0 || (size_t)metadata_size >= sizeof(metadata)) {
        framebuffer_capture_error = "framebuffer_metadata_encoding";
        goto cleanup;
    }
    metadata_file = CreateFileA(metadata_path, GENERIC_WRITE, 0, NULL,
                                CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (metadata_file == INVALID_HANDLE_VALUE) {
        framebuffer_capture_error = "framebuffer_metadata_create";
        goto cleanup;
    }
    metadata_created = TRUE;
    if (!write_handle_all(metadata_file, (const BYTE *)metadata,
                          (DWORD)metadata_size) ||
        !FlushFileBuffers(metadata_file)) {
        framebuffer_capture_error = "framebuffer_metadata_write";
        goto cleanup;
    }
    success = TRUE;

cleanup:
    if (raw_file != INVALID_HANDLE_VALUE) CloseHandle(raw_file);
    if (metadata_file != INVALID_HANDLE_VALUE) CloseHandle(metadata_file);
    if (native_raw_file != INVALID_HANDLE_VALUE) CloseHandle(native_raw_file);
    if (native_metadata_file != INVALID_HANDLE_VALUE) {
        CloseHandle(native_metadata_file);
    }
    if (canonical_pixels) HeapFree(GetProcessHeap(), 0, canonical_pixels);
    image_destructor(image);
    /* Cc.dll does not export its VC6 global operator delete.  The destructor
     * releases the owned framebuffer storage; the one outer object allocation
     * remains bounded to this single capture and dies with the scenario process
    * immediately after the completion event.  Calling a guessed CRT allocator
     * here would be an unsafe cross-module heap assumption. */
    if (!success) {
        if (raw_created) DeleteFileA(raw_path);
        if (metadata_created) DeleteFileA(metadata_path);
        if (native_raw_created) DeleteFileA(native_raw_path);
        if (native_metadata_created) DeleteFileA(native_metadata_path);
    }
    return success;
}

static void emit_framebuffer(DWORD tick, const BYTE digest[32])
{
    char line[384];
    char hash[65];
    DWORD sequence = next_id(&sequence_number);
    int size;
    encode_sha256(digest, hash);
    size = snprintf(
        line, sizeof(line),
        "MVT {\"record\":\"framebuffer\",\"sequence\":%lu,"
        "\"channel\":\"render.framebuffer\",\"tick\":%lu,"
        "\"values\":{\"raw_sha256\":\"%s\","
        "\"capture\":\"native_read_screen\"},"
        "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
        (unsigned long)sequence, (unsigned long)tick, hash,
        (unsigned long)GetCurrentThreadId());
    if (size > 0 && (size_t)size < sizeof(line)) append_record(line, (DWORD)size);
}

static BOOL framebuffer_capture_required(void)
{
    return !scenario_bounded_observation;
}

static void __attribute__((used)) record_render_final(DWORD controller_address,
                                                       DWORD device_address)
{
    DWORD last_error = GetLastError();
    ObserverThread *context = thread_context();
    char line[TRACE_LINE_SIZE];
    BYTE crash_requested = 0u;
    BYTE crash_active = 0u;
    DWORD crash_timer = 0u;
    DWORD frame;
    DWORD sequence;
    DWORD tick;
    int size;
    if (session_state != SESSION_READY || !context) {
        SetLastError(last_error);
        return;
    }
    if (render_checkpoint_tick == context->tick) {
        SetLastError(last_error);
        return;
    }
    render_checkpoint_tick = context->tick;
    tick = context->tick;
    if (!calibration_observation_only) {
        frame = next_id(&frame_number);
        sequence = next_id(&sequence_number);
        read_byte(controller_address, 0x48fdu, &crash_requested);
        read_byte(controller_address, 0x48feu, &crash_active);
        copy_readable((const void *)(ULONG_PTR)(controller_address + 0x4900u),
                      (BYTE *)&crash_timer, sizeof(crash_timer));
        size = snprintf(
            line, sizeof(line),
            "MVT {\"record\":\"behavior\",\"sequence\":%lu,"
            "\"channel\":\"render.final\",\"tick\":%lu,\"frame\":%lu,"
            "\"values\":{\"crash_requested\":%u,\"crash_active\":%u,"
            "\"crash_timer_f32_bits\":\"0x%08lx\"},"
            "\"diagnostics\":{\"thread_id\":%lu}}\r\n",
            (unsigned long)sequence, (unsigned long)tick, (unsigned long)frame,
            (unsigned int)crash_requested, (unsigned int)crash_active,
            (unsigned long)crash_timer, (unsigned long)GetCurrentThreadId());
        if (size > 0 && (size_t)size < sizeof(line)) {
            append_record(line, (DWORD)size);
        }
    }
    if (framebuffer_capture_required() &&
        session_state == SESSION_READY &&
        replay_active_tick == replay_capture_tick && !frame_captured) {
        BYTE digest[32];
        if (!capture_framebuffer(device_address, replay_active_tick, digest)) {
            session_fail(framebuffer_capture_error ? framebuffer_capture_error :
                         "framebuffer_capture");
        } else {
            frame_captured = TRUE;
            emit_framebuffer(replay_active_tick, digest);
        }
    }
    SetLastError(last_error);
}

static void complete_session_after_render(void)
{
    if (session_state == SESSION_READY &&
        replay_active_tick == replay_complete_tick &&
        replay_next_tick == replay_tick_count) {
        if (post_natural_edge_input_is_suspended()) {
            if (!suspend_post_natural_edge_input_contract(
                    replay_active_tick)) {
                session_fail(
                    "post_natural_edge_input_suspension_contract");
            } else {
                emit_natural_session("complete", "DIAGNOSTIC_ONLY");
                emit_session(
                    "diagnostic_complete",
                    "post_natural_edge_input_contract_suspended");
                write_marker("SCENARIO_DIAGNOSTIC_COMPLETE");
                flush_trace();
                if (trace_saturated) {
                    session_fail("trace_saturated");
                } else if (trace_write_failed) {
                    session_fail("trace_write");
                } else {
                    session_state = SESSION_COMPLETE;
                    if (replay_focus_stop_event) {
                        SetEvent(replay_focus_stop_event);
                    }
                    destroy_focus_sink_on_owner_thread();
                    SetEvent(complete_event);
                }
            }
        } else if (framebuffer_capture_required() && !frame_captured) {
            session_fail("framebuffer_missing");
        } else if ((DWORD)InterlockedCompareExchange(
                       &replay_focus_next_event, 0, 0) !=
                       replay_focus_event_count ||
                   InterlockedCompareExchange(
                       &replay_focus_scheduler_state, 0, 0) != 0) {
            session_fail("focus_timeline_completion_contract");
        } else if (!os_input_initialized || os_input_keys != 0u ||
                   os_input_scripted_keys != 0u ||
                   os_input_target_focus != 1u ||
                   os_input_target_tick != replay_complete_tick) {
            session_fail("input_release_missing");
        } else if (trace_saturated) {
            session_fail("trace_saturated");
        } else if (natural_capture_edge &&
                   InterlockedCompareExchange(
                       &natural_transition_emitted, 0, 0) != 1) {
            session_fail("natural_transition_source_missing");
        } else {
            emit_rng("end", rng_draw_count, rng_draw_count, NULL);
            emit_natural_session("complete", "PASS");
            emit_session("complete", "semantic_tick_and_frame");
            write_marker("SCENARIO_COMPLETE");
            flush_trace();
            if (trace_write_failed) {
                session_fail("trace_write");
            } else {
                session_state = SESSION_COMPLETE;
                if (replay_focus_stop_event) {
                    SetEvent(replay_focus_stop_event);
                }
                destroy_focus_sink_on_owner_thread();
                SetEvent(complete_event);
            }
        }
    }
}

static const BodyModeLifecycle *body_mode_for_vtable(DWORD vtable)
{
    DWORD index;
    for (index = 0u; index < BODY_MODE_COUNT; ++index) {
        if (BODY_MODE_LIFECYCLES[index].vtable == vtable) {
            return &BODY_MODE_LIFECYCLES[index];
        }
    }
    return NULL;
}

static BodyLifecycleThread *body_lifecycle_thread(BOOL create)
{
    DWORD index;
    LONG thread_id = (LONG)GetCurrentThreadId();
    for (index = 0u; index < BODY_THREAD_CONTEXT_COUNT; ++index) {
        if (body_lifecycle_threads[index].owner_thread_id == thread_id) {
            return &body_lifecycle_threads[index];
        }
    }
    if (!create) return NULL;
    for (index = 0u; index < BODY_THREAD_CONTEXT_COUNT; ++index) {
        BodyLifecycleThread *context = &body_lifecycle_threads[index];
        if (InterlockedCompareExchange(
                &context->owner_thread_id, thread_id, 0) == 0) {
            context->depth = 0u;
            return context;
        }
    }
    return NULL;
}

static void emit_body_lifecycle(const BodyLifecycleFrame *frame,
                                const char *edge)
{
    char line[768];
    DWORD sequence = next_id(&body_sequence_number);
    int size = snprintf(
        line, sizeof(line),
        "MVB {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-body-lifecycle\","
        "\"sequence\":%lu,\"evidence_scope\":\"BODY_ONLY\","
        "\"natural_transition_evidence\":false,"
        "\"mode_id\":\"%s\",\"object\":\"0x%08lx\","
        "\"vtable\":\"0x%08lx\",\"phase\":\"%s\","
        "\"entry\":\"0x%08lx\",\"edge\":\"%s\","
        "\"thread\":%lu,\"tick\":%lu,\"depth\":%lu}\r\n",
        (unsigned long)sequence, frame->mode->mode_id,
        (unsigned long)frame->object, (unsigned long)frame->vtable,
        BODY_PHASE_NAMES[frame->phase], (unsigned long)frame->entry, edge,
        (unsigned long)frame->thread, (unsigned long)frame->tick,
        (unsigned long)frame->depth);
    if (size > 0 && (size_t)size < sizeof(line)) {
        append_record(line, (DWORD)size);
    }
}

/* Return bit 31 marks that the synthetic leave return was armed.  Reviewed
 * native entries are all below 0x80000000, so the mark cannot alias an entry.
 * Calls from any non-engine thread retain the exact original dispatch and are
 * deliberately absent from BODY evidence. */
static DWORD __attribute__((used)) body_lifecycle_enter(
    DWORD object, DWORD phase_value, DWORD return_address)
{
    DWORD last_error = GetLastError();
    DWORD vtable = 0u;
    DWORD thread = GetCurrentThreadId();
    DWORD engine_thread = (DWORD)InterlockedCompareExchange(
        &engine_thread_id, 0, 0);
    BodyPhase phase = (BodyPhase)phase_value;
    const BodyModeLifecycle *mode;
    BodyLifecycleThread *context;
    BodyLifecycleFrame *frame;
    DWORD entry;
    if (phase_value >= BODY_PHASE_COUNT ||
        !read_pointer(object, 0u, &vtable) ||
        (mode = body_mode_for_vtable(vtable)) == NULL) {
        session_fail("body_lifecycle_identity_contract");
        SetLastError(last_error);
        return 0u;
    }
    entry = mode->entries[phase];
    if (body_dispatch_state == BODY_DISPATCH_DISABLED ||
        engine_thread == 0u || thread != engine_thread) {
        SetLastError(last_error);
        return entry;
    }
    /* A BODY suite launch records only its requested target.  This excludes
     * startup-login teardown from a later mode_login capture while preserving
     * the naturally activated barn's LOAD/OPEN records for the barn no-op
     * entry callback. */
    if (strcmp(mode->mode_name, body_mode_name) != 0 ||
        (strcmp(body_mode_name, "mode_barn") != 0 &&
         body_dispatch_state < BODY_DISPATCH_IN_ENTRY_CALLBACK) ||
        body_dispatch_state == BODY_DISPATCH_COMPLETE ||
        body_dispatch_state == BODY_DISPATCH_FAILED) {
        SetLastError(last_error);
        return entry;
    }
    context = body_lifecycle_thread(TRUE);
    if (!context || context->depth >= BODY_CALL_DEPTH) {
        session_fail("body_lifecycle_depth_contract");
        SetLastError(last_error);
        return entry;
    }
    frame = &context->frames[context->depth];
    frame->mode = mode;
    frame->object = object;
    frame->vtable = vtable;
    frame->entry = entry;
    frame->return_address = return_address;
    frame->thread = thread;
    frame->tick = (DWORD)InterlockedCompareExchange(
        &manager_tick_count, 0, 0);
    frame->depth = context->depth;
    frame->phase = phase;
    ++context->depth;
    emit_body_lifecycle(frame, "ENTER");
    SetLastError(last_error);
    return entry | BODY_ENTRY_RECORDED;
}

static DWORD __attribute__((used)) body_lifecycle_leave(void)
{
    DWORD last_error = GetLastError();
    DWORD thread = GetCurrentThreadId();
    BodyLifecycleThread *context = body_lifecycle_thread(FALSE);
    BodyLifecycleFrame *frame;
    DWORD return_address;
    DWORD mode_index;
    if (!context || context->depth == 0u ||
        (DWORD)InterlockedCompareExchange(&engine_thread_id, 0, 0) != thread) {
        session_fail("body_lifecycle_pair_contract");
        SetLastError(last_error);
        return 0u;
    }
    --context->depth;
    frame = &context->frames[context->depth];
    return_address = frame->return_address;
    emit_body_lifecycle(frame, "LEAVE");
    mode_index = (DWORD)(frame->mode - BODY_MODE_LIFECYCLES);
    if (mode_index >= BODY_MODE_COUNT ||
        body_lifecycle_counts[mode_index][frame->phase] == 0xffffffffu) {
        session_fail("body_lifecycle_count_contract");
    } else {
        ++body_lifecycle_counts[mode_index][frame->phase];
        body_lifecycle_last_leave_ticks[mode_index][frame->phase] =
            frame->tick;
    }
    SetLastError(last_error);
    return return_address;
}

#define BODY_LIFECYCLE_HOOK(name, phase) \
static void __attribute__((naked)) name(void) \
{ \
    __asm__ __volatile__( \
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t" \
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t" \
        "pushl 36(%ebx)\n\tpushl $" #phase "\n\tpushl 24(%ebx)\n\t" \
        "call _body_lifecycle_enter\n\taddl $12, %esp\n\t" \
        "movl %eax, 28(%ebx)\n\tfxrstor (%esp)\n\tmovl %ebx, %esp\n\t" \
        "popal\n\tpopfl\n\ttestl %eax, %eax\n\tjns 1f\n\t" \
        "andl $0x7fffffff, %eax\n\t" \
        "movl $_body_lifecycle_leave_hook, (%esp)\n\t" \
        "1:\n\tjmp *%eax\n\t"); \
}

BODY_LIFECYCLE_HOOK(body_load_hook, 0)
BODY_LIFECYCLE_HOOK(body_open_hook, 1)
BODY_LIFECYCLE_HOOK(body_tick_hook, 2)
BODY_LIFECYCLE_HOOK(body_render_hook, 3)
BODY_LIFECYCLE_HOOK(body_close_hook, 4)
BODY_LIFECYCLE_HOOK(body_unload_hook, 5)
#undef BODY_LIFECYCLE_HOOK

static void __attribute__((naked, used)) body_lifecycle_leave_hook(void)
{
    __asm__ __volatile__(
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $12, %esp\n\tcall _body_lifecycle_leave\n\taddl $12, %esp\n\t"
        /* ECX is caller-clobbered; EAX/EDX and x87 retain native returns. */
        "movl %eax, 24(%ebx)\n\tfxrstor (%esp)\n\tmovl %ebx, %esp\n\t"
        "popal\n\tpopfl\n\tjmp *%ecx\n\t");
}

static const char *scene_dispatch_kind_name(SceneDispatchRecordKind kind)
{
    if (kind == SCENE_RECORD_DISPATCH) return "DISPATCH";
    if (kind == SCENE_RECORD_ROOT_START) return "ROOT_START";
    if (kind == SCENE_RECORD_ROOT_UPDATE) return "ROOT_UPDATE";
    return "INVALID";
}

static const char *scene_dispatch_route_name(SceneDispatchRoute route)
{
    if (route == SCENE_ROUTE_GROUND) return "GROUND";
    if (route == SCENE_ROUTE_BARN) return "BARN";
    if (route == SCENE_ROUTE_FLIGHT) return "FLIGHT";
    return NULL;
}

static SceneDispatchThread *scene_dispatch_thread(BOOL create)
{
    DWORD index;
    LONG thread_id = (LONG)GetCurrentThreadId();
    for (index = 0u; index < SCENE_DISPATCH_THREAD_CONTEXT_COUNT; ++index) {
        if (scene_dispatch_threads[index].owner_thread_id == thread_id) {
            return &scene_dispatch_threads[index];
        }
    }
    if (!create) return NULL;
    for (index = 0u; index < SCENE_DISPATCH_THREAD_CONTEXT_COUNT; ++index) {
        SceneDispatchThread *context = &scene_dispatch_threads[index];
        if (InterlockedCompareExchange(
                &context->owner_thread_id, thread_id, 0) == 0) {
            context->depth = 0u;
            return context;
        }
    }
    return NULL;
}

static BOOL read_scene_root_state(DWORD root, SceneDispatchSnapshot *snapshot)
{
    BYTE complete = 0u, running = 0u;
    if (root == 0u) return FALSE;
    if (!read_byte(root, 0x08u, &complete) ||
        !read_byte(root, 0x28u, &running) ||
        !read_pointer(root, 0x24u, &snapshot->root_current) ||
        !read_pointer(root, 0x30u, &snapshot->root_next)) return FALSE;
    snapshot->root_complete = complete != 0u;
    snapshot->root_running = running != 0u;
    return TRUE;
}

static BOOL read_barn_tail(DWORD root, DWORD *tail)
{
    DWORD current = root;
    DWORD count = 0u;
    while (current != 0u && count++ < 4096u) {
        DWORD next = 0u;
        if (!read_pointer(current, 0x30u, &next)) return FALSE;
        if (next == 0u) {
            *tail = current;
            return TRUE;
        }
        if (next == current) return FALSE;
        current = next;
    }
    if (root == 0u) {
        *tail = 0u;
        return TRUE;
    }
    return FALSE;
}

static BOOL read_scene_dispatch_snapshot(
    SceneDispatchRecordKind kind, SceneDispatchRoute route,
    DWORD object, DWORD root, SceneDispatchSnapshot *snapshot)
{
    BYTE special_byte = 0u;
    memset(snapshot, 0, sizeof(*snapshot));
    if (kind != SCENE_RECORD_DISPATCH) {
        snapshot->valid =
            read_pointer(root, 0u, &snapshot->object_vtable) &&
            read_scene_root_state(root, snapshot);
        return snapshot->valid;
    }
    if (!read_pointer(object, 0u, &snapshot->object_vtable)) return FALSE;
    if (route == SCENE_ROUTE_GROUND) {
        snapshot->valid =
            read_pointer(object, 0x8c4u, &snapshot->queue_0) &&
            read_pointer(object, 0x8c8u, &snapshot->queue_1) &&
            read_pointer(object, 0x8d0u, &snapshot->queue_2) &&
            read_pointer(object, 0x8d4u, &snapshot->queue_3);
    } else if (route == SCENE_ROUTE_BARN) {
        snapshot->valid =
            read_pointer(object, 0x1aecu, &snapshot->queue_0) &&
            read_barn_tail(snapshot->queue_0, &snapshot->queue_1);
    } else if (route == SCENE_ROUTE_FLIGHT) {
        snapshot->valid =
            read_pointer(object, 0x3fc0u, &snapshot->queue_0);
    } else {
        return FALSE;
    }
    if (!snapshot->valid) return FALSE;
    if (snapshot->object_vtable == 0x0044d718u) {
        snapshot->valid =
            read_pointer(object, 0x48a0u, &snapshot->special_0) &&
            read_byte(object, 0x48a4u, &special_byte);
        snapshot->special_1 = special_byte != 0u;
    } else if (snapshot->object_vtable == 0x0044d7a0u) {
        snapshot->valid =
            read_pointer(object, 0x4898u, &snapshot->special_0) &&
            read_byte(object, 0x489cu, &special_byte);
        snapshot->special_1 = special_byte != 0u;
    } else if (snapshot->object_vtable == 0x0044d948u) {
        snapshot->valid = read_byte(object, 0x48acu, &special_byte);
        snapshot->special_0 = special_byte != 0u;
        snapshot->special_1 = 0u;
    }
    if (root != 0u && !read_scene_root_state(root, snapshot)) {
        snapshot->valid = FALSE;
    }
    return snapshot->valid;
}

static BOOL resolve_scene_root_name(DWORD root, char name[SCENE_ROOT_NAME_SIZE])
{
    DWORD pointer = 0u, index;
    if (root == 0u || !read_pointer(root, 0x2cu, &pointer) || pointer == 0u) {
        return FALSE;
    }
    for (index = 0u; index < SCENE_ROOT_NAME_SIZE; ++index) {
        BYTE character = 0u;
        if (pointer > MAXDWORD - index ||
            !copy_readable((const void *)(ULONG_PTR)(pointer + index),
                           &character, 1u)) return FALSE;
        if (character == 0u) {
            name[index] = '\0';
            return index != 0u;
        }
        if (!((character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') ||
              character == '_' || character == '-' || character == '.')) {
            return FALSE;
        }
        name[index] = (char)character;
    }
    return FALSE;
}

static const char *scene_special_policy(DWORD vtable, const char **status)
{
    if (vtable == 0x0044d718u) {
        *status = "ROOT_AND_ARM_FLAG_SNAPSHOT";
        return "GROTTE_REFUEL";
    }
    if (vtable == 0x0044d7a0u) {
        *status = "RESULT_AND_FIRST_VISIT_SNAPSHOT";
        return "RAYMOND_CHALLENGE";
    }
    if (vtable == 0x0044d948u) {
        *status = "OUTRO_FLAG_ONLY_PROJECTED_X_UNRESOLVED";
        return "EXHIBITION_SELECTOR";
    }
    *status = "NOT_SPECIAL";
    return "GENERIC";
}

static void emit_scene_dispatch(
    const SceneDispatchFrame *frame, const SceneDispatchSnapshot *after)
{
    char line[TRACE_LINE_SIZE];
    char root_name[SCENE_ROOT_NAME_SIZE];
    char root_name_json[SCENE_ROOT_NAME_SIZE + 3u];
    const char *route = scene_dispatch_route_name(frame->route);
    const char *policy_status;
    const char *policy = scene_special_policy(
        frame->before.object_vtable != 0u ? frame->before.object_vtable :
                                           after->object_vtable,
        &policy_status);
    DWORD sequence;
    DWORD engine_thread = (DWORD)InterlockedCompareExchange(
        &engine_thread_id, 0, 0);
    BOOL name_resolved = resolve_scene_root_name(frame->root, root_name);
    BOOL observed = frame->before.valid && after->valid;
    int size;
    if (name_resolved) snprintf(root_name_json, sizeof(root_name_json),
                                "\"%s\"", root_name);
    else strcpy(root_name_json, "null");
    if (!trace_lock_ready) return;
    EnterCriticalSection(&trace_lock);
    sequence = next_id(&scene_dispatch_sequence_number);
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-scene-dispatch\","
        "\"sequence\":%lu,\"evidence_scope\":\"SCENE_DISPATCH_ONLY\","
        "\"natural_transition_evidence\":false,"
        "\"body_evidence\":false,\"observation_status\":\"%s\","
        "\"call_id\":%lu,\"record_kind\":\"%s\",\"route\":%s%s%s,"
        "\"object\":\"0x%08lx\",\"object_vtable\":\"0x%08lx\","
        "\"root\":\"0x%08lx\","
        "\"root_name\":%s,\"root_name_status\":\"%s\","
        "\"caller\":\"0x%08lx\",\"thread\":%lu,"
        "\"manager_thread\":%s,\"manager_tick\":%lu,"
        "\"depth\":%lu,\"dt_f32_bits\":\"0x%08lx\","
        "\"before\":{\"valid\":%s,"
        "\"queue\":[\"0x%08lx\",\"0x%08lx\",\"0x%08lx\",\"0x%08lx\"],"
        "\"root_complete\":%lu,\"root_running\":%lu,"
        "\"root_current\":\"0x%08lx\",\"root_next\":\"0x%08lx\"},"
        "\"after\":{\"valid\":%s,"
        "\"queue\":[\"0x%08lx\",\"0x%08lx\",\"0x%08lx\",\"0x%08lx\"],"
        "\"root_complete\":%lu,\"root_running\":%lu,"
        "\"root_current\":\"0x%08lx\",\"root_next\":\"0x%08lx\"},"
        "\"special_policy\":{\"policy\":\"%s\","
        "\"semantic_status\":\"%s\","
        "\"before\":[\"0x%08lx\",\"0x%08lx\"],"
        "\"after\":[\"0x%08lx\",\"0x%08lx\"]}}\r\n",
        (unsigned long)sequence, observed ? "OBSERVED" : "UNRESOLVED",
        (unsigned long)sequence, scene_dispatch_kind_name(frame->kind),
        route ? "\"" : "", route ? route : "null", route ? "\"" : "",
        (unsigned long)frame->object,
        (unsigned long)(frame->before.object_vtable != 0u ?
                            frame->before.object_vtable : after->object_vtable),
        (unsigned long)frame->root,
        root_name_json, name_resolved ? "RESOLVED" : "UNRESOLVED",
        (unsigned long)frame->return_address,
        (unsigned long)frame->thread,
        engine_thread != 0u && engine_thread == frame->thread ? "true" : "false",
        (unsigned long)frame->tick, (unsigned long)frame->depth,
        (unsigned long)frame->dt_f32_bits,
        frame->before.valid ? "true" : "false",
        (unsigned long)frame->before.queue_0,
        (unsigned long)frame->before.queue_1,
        (unsigned long)frame->before.queue_2,
        (unsigned long)frame->before.queue_3,
        (unsigned long)frame->before.root_complete,
        (unsigned long)frame->before.root_running,
        (unsigned long)frame->before.root_current,
        (unsigned long)frame->before.root_next,
        after->valid ? "true" : "false",
        (unsigned long)after->queue_0, (unsigned long)after->queue_1,
        (unsigned long)after->queue_2, (unsigned long)after->queue_3,
        (unsigned long)after->root_complete,
        (unsigned long)after->root_running,
        (unsigned long)after->root_current,
        (unsigned long)after->root_next,
        policy, policy_status,
        (unsigned long)frame->before.special_0,
        (unsigned long)frame->before.special_1,
        (unsigned long)after->special_0,
        (unsigned long)after->special_1);
    if (size > 0 && (size_t)size < sizeof(line)) {
        append_record_locked(line, (DWORD)size);
    }
    LeaveCriticalSection(&trace_lock);
    if (size <= 0 || (size_t)size >= sizeof(line)) {
        session_fail("scene_dispatch_trace_line_contract");
    }
}

static void __attribute__((naked, used)) scene_dispatch_leave_hook(void);

static void __attribute__((used)) scene_dispatch_enter(
    DWORD kind_value, DWORD route_value, DWORD object, DWORD root,
    DWORD dt_f32_bits, DWORD *return_slot)
{
    DWORD last_error = GetLastError();
    SceneDispatchThread *context;
    SceneDispatchFrame *frame;
    if (!scene_dispatch_observation_enabled || !return_slot ||
        kind_value > SCENE_RECORD_ROOT_UPDATE ||
        route_value > SCENE_ROUTE_FLIGHT ||
        (kind_value == SCENE_RECORD_DISPATCH &&
         route_value == SCENE_ROUTE_NONE) ||
        (kind_value != SCENE_RECORD_DISPATCH &&
         route_value != SCENE_ROUTE_NONE)) goto done;
    if (kind_value == SCENE_RECORD_DISPATCH && native_dispatch_armed) {
        mvds_observe_route((MvdsRoute)route_value, object, root);
    }
    context = scene_dispatch_thread(TRUE);
    if (!context || context->depth >= SCENE_DISPATCH_CALL_DEPTH) {
        session_fail("scene_dispatch_depth_contract");
        goto done;
    }
    frame = &context->frames[context->depth];
    memset(frame, 0, sizeof(*frame));
    frame->kind = (SceneDispatchRecordKind)kind_value;
    frame->route = (SceneDispatchRoute)route_value;
    frame->object = object;
    frame->root = root;
    frame->return_address = *return_slot;
    frame->thread = GetCurrentThreadId();
    frame->tick = (DWORD)InterlockedCompareExchange(
        &manager_tick_count, 0, 0);
    frame->depth = context->depth;
    frame->dt_f32_bits = dt_f32_bits;
    read_scene_dispatch_snapshot(frame->kind, frame->route, object, root,
                                 &frame->before);
    ++context->depth;
    *return_slot = (DWORD)(ULONG_PTR)&scene_dispatch_leave_hook;
done:
    SetLastError(last_error);
}

static DWORD __attribute__((used)) scene_dispatch_leave(void)
{
    DWORD last_error = GetLastError();
    SceneDispatchThread *context = scene_dispatch_thread(FALSE);
    SceneDispatchFrame *frame;
    SceneDispatchSnapshot after;
    DWORD return_address;
    if (!context || context->depth == 0u) {
        session_fail("scene_dispatch_pair_contract");
        SetLastError(last_error);
        return 0u;
    }
    --context->depth;
    frame = &context->frames[context->depth];
    return_address = frame->return_address;
    read_scene_dispatch_snapshot(frame->kind, frame->route,
                                 frame->object, frame->root, &after);
    emit_scene_dispatch(frame, &after);
    SetLastError(last_error);
    return return_address;
}

#define SCENE_DISPATCH_HOOK(name, kind, route, root_argument, dt_argument, trampoline) \
static void __attribute__((naked)) name(void) \
{ \
    __asm__ __volatile__( \
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t" \
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t" \
        "subl $8, %esp\n\tleal 36(%ebx), %eax\n\tpushl %eax\n\t" \
        "pushl " dt_argument "\n\tpushl " root_argument "\n\t" \
        "pushl 24(%ebx)\n\tpushl $" #route "\n\tpushl $" #kind "\n\t" \
        "call _scene_dispatch_enter\n\taddl $32, %esp\n\t" \
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t" \
        "jmp *" trampoline "\n\t"); \
}

SCENE_DISPATCH_HOOK(scene_dispatch_ground_hook, 0, 1,
                    "40(%ebx)", "$0", "_scene_dispatch_ground_trampoline")
SCENE_DISPATCH_HOOK(scene_dispatch_barn_hook, 0, 2,
                    "40(%ebx)", "$0", "_scene_dispatch_barn_trampoline")
SCENE_DISPATCH_HOOK(scene_dispatch_flight_hook, 0, 3,
                    "40(%ebx)", "$0", "_scene_dispatch_flight_trampoline")
SCENE_DISPATCH_HOOK(udsp_root_start_hook, 1, 0,
                    "24(%ebx)", "$0", "_udsp_root_start_trampoline")
SCENE_DISPATCH_HOOK(udsp_root_update_hook, 2, 0,
                    "24(%ebx)", "40(%ebx)", "_udsp_root_update_trampoline")
#undef SCENE_DISPATCH_HOOK

static void __attribute__((naked, used)) scene_dispatch_leave_hook(void)
{
    __asm__ __volatile__(
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $12, %esp\n\tcall _scene_dispatch_leave\n\taddl $12, %esp\n\t"
        "movl %eax, 24(%ebx)\n\tfxrstor (%esp)\n\tmovl %ebx, %esp\n\t"
        "popal\n\tpopfl\n\tjmp *%ecx\n\t");
}

static const UdspCommandClassifier *udsp_command_for_opcode(DWORD opcode)
{
    DWORD index;
    for (index = 0u; index < UDSP_COMMAND_COUNT; ++index) {
        if (UDSP_COMMANDS[index].opcode == opcode) return &UDSP_COMMANDS[index];
    }
    return NULL;
}

static UdspThread *udsp_thread(BOOL create)
{
    DWORD index;
    LONG thread_id = (LONG)GetCurrentThreadId();
    for (index = 0u; index < UDSP_THREAD_CONTEXT_COUNT; ++index) {
        if (udsp_threads[index].owner_thread_id == thread_id) {
            return &udsp_threads[index];
        }
    }
    if (!create) return NULL;
    for (index = 0u; index < UDSP_THREAD_CONTEXT_COUNT; ++index) {
        UdspThread *context = &udsp_threads[index];
        if (InterlockedCompareExchange(
                &context->owner_thread_id, thread_id, 0) == 0) {
            context->depth = 0u;
            return context;
        }
    }
    return NULL;
}

static void __attribute__((used)) position_character_write_before(
    DWORD head, DWORD command_context, DWORD command_node)
{
    DWORD last_error = GetLastError();
    DWORD node_context = 0u, context_head = 0u;
    UdspThread *context = udsp_thread(FALSE);
    UdspFrame *frame;
    if (!context || context->depth == 0u) {
        session_fail("position_character_udsp_frame_contract");
        goto done;
    }
    frame = &context->frames[context->depth - 1u];
    if (!frame->command || frame->command->opcode != 9u ||
        frame->node != command_node || frame->position_write_observed ||
        head == 0u || command_context == 0u ||
        !read_pointer(command_node, 0x20u, &node_context) ||
        !read_pointer(command_context, 0x4a0u, &context_head) ||
        node_context != command_context || context_head != head ||
        !read_pointer(head, 0u, &frame->position_prior_x_f32_bits) ||
        !read_pointer(head, 4u, &frame->position_prior_y_f32_bits)) {
        session_fail("position_character_write_boundary_contract");
        goto done;
    }
    frame->position_write_observed = TRUE;
    frame->position_head = head;
    frame->position_context = command_context;
done:
    SetLastError(last_error);
}

static void record_position_character_commit(const UdspFrame *frame,
                                             const UdspSnapshot *after)
{
    DWORD last_error = GetLastError();
    DWORD head = 0u, committed_x = 0u, committed_y = 0u;
    DWORD resolved[2] = {0u, 0u};
    DWORD *resolve_result;
    DWORD chain_count = 0u, mirror_subtractions = 0u;
    DWORD seen[64];
    DWORD current;
    BYTE dirty = 0u;
    Sha256Context chain_hash;
    BYTE chain_digest[32];
    char chain_digest_text[65];
    char line[TRACE_LINE_SIZE];
    DWORD sequence;
    int size;

    if (!after || after->context == 0u ||
        !read_pointer(after->context, 0x4a0u, &head) ||
        !read_byte(after->context, 0x48eu, &dirty) || dirty != 1u) {
        session_fail("position_character_commit_context_contract");
        goto done;
    }
    if (head == 0u) {
        if (frame->position_write_observed) {
            session_fail("position_character_null_head_contract");
            goto done;
        }
        sequence = next_id(&diagnostic_sequence_number);
        size = snprintf(
            line, sizeof(line),
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-position-character\","
            "\"sequence\":%lu,\"call_id\":%lu,\"tick\":%lu,"
            "\"write_site\":\"0x0043c6f6\","
            "\"resolve_site\":\"0x0041ad50\","
            "\"write_observed\":false,\"dirty_u8\":1,"
            "\"payload_f32\":[\"0x%08lx\",\"0x%08lx\"],"
            "\"committed_f32\":null,\"resolved_f32\":null,"
            "\"chain_count\":0,\"mirror_subtractions\":0,"
            "\"chain_sha256\":null,\"thread_id\":%lu}\r\n",
            (unsigned long)sequence, (unsigned long)frame->call_id,
            (unsigned long)frame->tick,
            (unsigned long)after->payload[0],
            (unsigned long)after->payload[1],
            (unsigned long)GetCurrentThreadId());
        if (size <= 0 || (size_t)size >= sizeof(line)) {
            session_fail("position_character_trace_line_contract");
        } else {
            append_record(line, (DWORD)size);
        }
        goto done;
    }
    if (!frame->position_write_observed || frame->position_head != head ||
        frame->position_context != after->context ||
        !read_pointer(head, 0u, &committed_x) ||
        !read_pointer(head, 4u, &committed_y) ||
        committed_x != after->payload[0] || committed_y != after->payload[1]) {
        session_fail("position_character_commit_write_contract");
        goto done;
    }

    sha256_init(&chain_hash);
    current = head;
    while (current != 0u) {
        DWORD local_x, local_y, parent, owner_context, owner_head;
        DWORD row[5];
        DWORD index;
        BYTE mirror;
        if (chain_count >= sizeof(seen) / sizeof(seen[0]) ||
            !read_pointer(current, 0u, &local_x) ||
            !read_pointer(current, 4u, &local_y) ||
            !read_pointer(current, 0x1cu, &parent) ||
            !read_pointer(current, 0x28u, &owner_context) ||
            owner_context == 0u ||
            !read_byte(owner_context, 0x48du, &mirror) ||
            !read_pointer(owner_context, 0x4a0u, &owner_head)) {
            session_fail("position_character_chain_contract");
            goto done;
        }
        for (index = 0u; index < chain_count; ++index) {
            if (seen[index] == current) {
                session_fail("position_character_chain_cycle_contract");
                goto done;
            }
        }
        seen[chain_count] = current;
        row[0] = chain_count;
        row[1] = local_x;
        row[2] = local_y;
        row[3] = mirror != 0u ? 1u : 0u;
        row[4] = current == owner_head ? 1u : 0u;
        sha256_update(&chain_hash, (const BYTE *)row, sizeof(row));
        if (mirror != 0u && current != owner_head) ++mirror_subtractions;
        ++chain_count;
        current = parent;
    }
    sha256_final(&chain_hash, chain_digest);
    encode_sha256(chain_digest, chain_digest_text);
    resolve_result = ((PositionResolveFunction)(ULONG_PTR)
        POSITION_CHARACTER_RESOLVE)((void *)(ULONG_PTR)head, resolved);
    if (resolve_result != resolved) {
        session_fail("position_character_native_resolve_contract");
        goto done;
    }
    sequence = next_id(&diagnostic_sequence_number);
    size = snprintf(
        line, sizeof(line),
        "MVD {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-position-character\","
        "\"sequence\":%lu,\"call_id\":%lu,\"tick\":%lu,"
        "\"write_site\":\"0x0043c6f6\","
        "\"resolve_site\":\"0x0041ad50\","
        "\"write_observed\":true,\"dirty_u8\":1,"
        "\"prior_f32\":[\"0x%08lx\",\"0x%08lx\"],"
        "\"payload_f32\":[\"0x%08lx\",\"0x%08lx\"],"
        "\"committed_f32\":[\"0x%08lx\",\"0x%08lx\"],"
        "\"resolved_f32\":[\"0x%08lx\",\"0x%08lx\"],"
        "\"chain_count\":%lu,\"mirror_subtractions\":%lu,"
        "\"chain_sha256\":\"%s\",\"thread_id\":%lu}\r\n",
        (unsigned long)sequence, (unsigned long)frame->call_id,
        (unsigned long)frame->tick,
        (unsigned long)frame->position_prior_x_f32_bits,
        (unsigned long)frame->position_prior_y_f32_bits,
        (unsigned long)after->payload[0],
        (unsigned long)after->payload[1],
        (unsigned long)committed_x, (unsigned long)committed_y,
        (unsigned long)resolved[0], (unsigned long)resolved[1],
        (unsigned long)chain_count, (unsigned long)mirror_subtractions,
        chain_digest_text, (unsigned long)GetCurrentThreadId());
    if (size <= 0 || (size_t)size >= sizeof(line)) {
        session_fail("position_character_trace_line_contract");
    } else {
        append_record(line, (DWORD)size);
        InterlockedIncrement(&position_character_record_count);
    }
done:
    SetLastError(last_error);
}

static BOOL read_udsp_u32(DWORD address, DWORD offset, DWORD *value)
{
    if (address == 0u || offset > MAXDWORD - address) return FALSE;
    return read_pointer(address, offset, value);
}

static BOOL read_udsp_byte(DWORD address, DWORD offset, BYTE *value)
{
    if (address == 0u || offset > MAXDWORD - address) return FALSE;
    return read_byte(address, offset, value);
}

static BOOL read_udsp_snapshot(DWORD composite, DWORD node,
                               UdspSnapshot *snapshot)
{
    BYTE complete, started, parent_complete;
    DWORD index;
    if (!read_udsp_byte(node, 0x08u, &complete) ||
        !read_udsp_byte(node, 0x50u, &started) ||
        !read_udsp_u32(node, 0x24u, &snapshot->modifier) ||
        !read_udsp_u32(node, 0x28u, &snapshot->timer_f32_bits) ||
        !read_udsp_u32(node, 0x20u, &snapshot->context) ||
        !read_udsp_u32(node, 0x10u, &snapshot->next) ||
        !read_udsp_u32(node, 0x18u, &snapshot->callback) ||
        !read_udsp_byte(composite, 0x08u, &parent_complete) ||
        !read_udsp_u32(composite, 0x24u, &snapshot->parent_current)) {
        return FALSE;
    }
    for (index = 0u; index < 5u; ++index) {
        if (!read_udsp_u32(node, 0x3cu + index * 4u,
                           &snapshot->payload[index])) return FALSE;
    }
    snapshot->complete = complete != 0u;
    snapshot->started = started != 0u;
    snapshot->parent_complete = parent_complete != 0u;
    return TRUE;
}

static void emit_udsp_command(const UdspFrame *frame,
                              const UdspSnapshot *snapshot,
                              const char *phase, const char *outcome,
                              BOOL advanced)
{
    char line[TRACE_LINE_SIZE];
    DWORD sequence;
    int size;
    if (!trace_lock_ready) {
        session_fail("udsp_trace_lock_contract");
        return;
    }
    /* Sequence assignment and append share the trace lock so records from
     * distinct game threads cannot be serialized out of sequence. */
    EnterCriticalSection(&trace_lock);
    sequence = next_id(&udsp_sequence_number);
    size = snprintf(
        line, sizeof(line),
        "MVU {\"schema\":1,"
        "\"protocol\":\"miel-vliegt-native-udsp-command\","
        "\"sequence\":%lu,\"evidence_scope\":\"UDSP_ONLY\","
        "\"natural_transition_evidence\":false,"
        "\"call_id\":%lu,\"phase\":\"%s\","
        "\"thread\":%lu,\"tick\":%lu,\"depth\":%lu,"
        "\"dispatcher\":\"0x0043c580\","
        "\"parser_case\":\"0x%08lx\","
        "\"handler_case\":\"0x%08lx\","
        "\"composite\":\"0x%08lx\",\"node\":\"0x%08lx\","
        "\"opcode_id\":%lu,\"opcode_name\":\"%s\","
        "\"dt_f32_bits\":\"0x%08lx\","
        "\"complete\":%s,\"started\":%s,\"modifier\":%lu,"
        "\"timer_f32_bits\":\"0x%08lx\","
        "\"context\":\"0x%08lx\",\"next\":\"0x%08lx\","
        "\"callback\":\"0x%08lx\","
        "\"payload\":[\"0x%08lx\",\"0x%08lx\",\"0x%08lx\","
        "\"0x%08lx\",\"0x%08lx\"],"
        "\"parent_complete\":%s,"
        "\"parent_current\":\"0x%08lx\","
        "\"advanced\":%s,\"outcome\":\"%s\"}\r\n",
        (unsigned long)sequence, (unsigned long)frame->call_id, phase,
        (unsigned long)frame->thread, (unsigned long)frame->tick,
        (unsigned long)frame->depth,
        (unsigned long)frame->command->parser_case,
        (unsigned long)frame->command->handler_case,
        (unsigned long)frame->composite, (unsigned long)frame->node,
        (unsigned long)frame->command->opcode, frame->command->name,
        (unsigned long)frame->dt_f32_bits,
        snapshot->complete ? "true" : "false",
        snapshot->started ? "true" : "false",
        (unsigned long)snapshot->modifier,
        (unsigned long)snapshot->timer_f32_bits,
        (unsigned long)snapshot->context, (unsigned long)snapshot->next,
        (unsigned long)snapshot->callback,
        (unsigned long)snapshot->payload[0],
        (unsigned long)snapshot->payload[1],
        (unsigned long)snapshot->payload[2],
        (unsigned long)snapshot->payload[3],
        (unsigned long)snapshot->payload[4],
        snapshot->parent_complete ? "true" : "false",
        (unsigned long)snapshot->parent_current,
        advanced ? "true" : "false", outcome);
    if (size > 0 && (size_t)size < sizeof(line)) {
        append_record_locked(line, (DWORD)size);
    }
    LeaveCriticalSection(&trace_lock);
    if (size <= 0 || (size_t)size >= sizeof(line)) {
        session_fail("udsp_trace_line_contract");
    }
}

static void __attribute__((naked, used)) udsp_dispatch_leave_hook(void);

static void __attribute__((used)) udsp_dispatch_enter(
    DWORD composite, DWORD dt_f32_bits, DWORD *return_slot)
{
    DWORD last_error = GetLastError();
    DWORD node = 0u, node_type = 0u, opcode = 0u;
    const UdspCommandClassifier *command;
    UdspThread *context;
    UdspFrame *frame;
    if (!return_slot ||
        !read_udsp_u32(composite, 0x24u, &node)) {
        session_fail("udsp_dispatch_pointer_contract");
        goto done;
    }
    if (node == 0u) goto done;
    if (!read_udsp_u32(node, 0x04u, &node_type)) {
        session_fail("udsp_node_type_contract");
        goto done;
    }
    if (node_type == 4u) goto done;
    if (node_type != 6u || !read_udsp_u32(node, 0x1cu, &opcode) ||
        (command = udsp_command_for_opcode(opcode)) == NULL) {
        session_fail("udsp_opcode_contract");
        goto done;
    }
    context = udsp_thread(TRUE);
    if (!context || context->depth >= UDSP_CALL_DEPTH) {
        session_fail("udsp_dispatch_depth_contract");
        goto done;
    }
    frame = &context->frames[context->depth];
    frame->command = command;
    frame->call_id = next_id(&udsp_call_number);
    frame->composite = composite;
    frame->node = node;
    frame->return_address = *return_slot;
    frame->thread = GetCurrentThreadId();
    frame->tick = (DWORD)InterlockedCompareExchange(
        &manager_tick_count, 0, 0);
    frame->depth = context->depth;
    frame->dt_f32_bits = dt_f32_bits;
    frame->position_write_observed = FALSE;
    frame->position_head = 0u;
    frame->position_context = 0u;
    frame->position_prior_x_f32_bits = 0u;
    frame->position_prior_y_f32_bits = 0u;
    if (!read_udsp_snapshot(composite, node, &frame->before)) {
        session_fail("udsp_before_snapshot_contract");
        goto done;
    }
    ++context->depth;
    emit_udsp_command(frame, &frame->before, "BEFORE", "PENDING", FALSE);
    *return_slot = (DWORD)(ULONG_PTR)&udsp_dispatch_leave_hook;
done:
    SetLastError(last_error);
}

static DWORD __attribute__((used)) udsp_dispatch_leave(void)
{
    DWORD last_error = GetLastError();
    UdspThread *context = udsp_thread(FALSE);
    UdspFrame *frame;
    UdspSnapshot after;
    DWORD return_address;
    BOOL advanced;
    const char *outcome;
    if (!context || context->depth == 0u) {
        session_fail("udsp_dispatch_pair_contract");
        SetLastError(last_error);
        return 0u;
    }
    --context->depth;
    frame = &context->frames[context->depth];
    return_address = frame->return_address;
    if (!read_udsp_snapshot(frame->composite, frame->node, &after)) {
        session_fail("udsp_after_snapshot_contract");
        SetLastError(last_error);
        return return_address;
    }
    advanced = after.parent_current != frame->before.parent_current;
    if (after.complete) outcome = "COMPLETE";
    else if (!frame->before.started && after.started) outcome = "STARTED";
    else outcome = "ACTIVE";
    if (frame->command->opcode == 9u && after.complete) {
        record_position_character_commit(frame, &after);
    }
    emit_udsp_command(frame, &after, "AFTER", outcome, advanced);
    SetLastError(last_error);
    return return_address;
}

static void __attribute__((naked)) udsp_dispatch_hook(void)
{
    __asm__ __volatile__(
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $4, %esp\n\tleal 36(%ebx), %eax\n\tpushl %eax\n\t"
        "pushl 40(%ebx)\n\tpushl 24(%ebx)\n\t"
        "call _udsp_dispatch_enter\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "jmp *_udsp_dispatch_trampoline\n\t");
}

static void __attribute__((naked)) position_character_write_hook(void)
{
    __asm__ __volatile__(
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $4, %esp\n\tpushl 4(%ebx)\n\tpushl 24(%ebx)\n\tpushl 28(%ebx)\n\t"
        "call _position_character_write_before\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "flds 60(%esi)\n\tfstps (%eax)\n\tfstps 4(%eax)\n\t"
        "jmp *_position_character_write_resume\n\t");
}

static void __attribute__((naked, used)) udsp_dispatch_leave_hook(void)
{
    __asm__ __volatile__(
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $12, %esp\n\tcall _udsp_dispatch_leave\n\taddl $12, %esp\n\t"
        "movl %eax, 24(%ebx)\n\tfxrstor (%esp)\n\tmovl %ebx, %esp\n\t"
        "popal\n\tpopfl\n\tjmp *%ecx\n\t");
}

static const DWORD PARTICLE_BASE_F32_OFFSETS[] = {
    0x08u, 0x0cu, 0x10u, 0x14u, 0x18u, 0x1cu,
    0x20u, 0x24u, 0x28u, 0x2cu, 0x30u, 0x34u,
    0x3cu, 0x40u, 0x44u, 0x4cu, 0x54u
};

static const DWORD PARTICLE_RENDER_F32_OFFSETS[] = {
    0x58u, 0x5cu, 0x60u, 0x70u, 0x74u, 0x78u, 0x84u, 0x88u,
    0x8cu, 0x94u, 0x98u, 0x9cu, 0xd0u, 0xd4u, 0xd8u
};

static BOOL particle_line_append(char *line, size_t capacity, int *used,
                                 const char *format, ...)
{
    va_list arguments;
    int added;
    if (*used < 0 || (size_t)*used >= capacity) return FALSE;
    va_start(arguments, format);
    added = vsnprintf(line + *used, capacity - (size_t)*used,
                      format, arguments);
    va_end(arguments);
    if (added < 0 || (size_t)added >= capacity - (size_t)*used) return FALSE;
    *used += added;
    return TRUE;
}

static const char *particle_type(DWORD vtable)
{
    if (vtable == 0x0044d34cu) return "flight-emitter";
    if (vtable == 0x0044d2a0u) return "flight-particle";
    return "unknown";
}

static BOOL append_particle_f32_values(char *line, size_t capacity, int *used,
                                       const BYTE *bytes)
{
    DWORD index;
    if (!particle_line_append(line, capacity, used, "[")) return FALSE;
    for (index = 0u;
         index < sizeof(PARTICLE_BASE_F32_OFFSETS) /
                     sizeof(PARTICLE_BASE_F32_OFFSETS[0]);
         ++index) {
        if (!particle_line_append(
                line, capacity, used, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)read_u32(
                    bytes, PARTICLE_BASE_F32_OFFSETS[index]))) return FALSE;
    }
    return particle_line_append(line, capacity, used, "]");
}

static BOOL append_particle_render_f32_values(
    char *line, size_t capacity, int *used, const BYTE *particle_bytes)
{
    BYTE render[0xdcu];
    DWORD render_address = read_u32(particle_bytes, 0x04u);
    DWORD index;
    BOOL present = render_address != 0u &&
        copy_readable((const void *)(ULONG_PTR)render_address,
                      render, sizeof(render)) == sizeof(render);
    if (!particle_line_append(
            line, capacity, used, ",\"render_present\":%s,\"render_f32\":[",
            present ? "true" : "false")) return FALSE;
    for (index = 0u;
         index < sizeof(PARTICLE_RENDER_F32_OFFSETS) /
                     sizeof(PARTICLE_RENDER_F32_OFFSETS[0]);
         ++index) {
        if (!particle_line_append(
                line, capacity, used, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)(present ? read_u32(
                    render, PARTICLE_RENDER_F32_OFFSETS[index]) : 0u))) {
            return FALSE;
        }
    }
    return particle_line_append(line, capacity, used, "]");
}

static void emit_particle_reset_snapshot(const char *phase,
                                         DWORD object_address,
                                         DWORD caller_site,
                                         DWORD reset_id)
{
    BYTE bytes[0x58u];
    char line[TRACE_LINE_SIZE];
    DWORD sequence;
    int size = 0;
    if (session_state != SESSION_READY || replay_active_tick == INVALID_ID ||
        copy_readable((const void *)(ULONG_PTR)object_address,
                      bytes, sizeof(bytes)) != sizeof(bytes)) return;
    sequence = next_id(&particle_sequence_number);
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-particle-lifecycle\","
            "\"sequence\":%lu,\"phase\":\"%s\",\"tick\":%lu,"
            "\"reset_id\":%lu,\"caller_site\":\"0x%08lx\","
            "\"type\":\"%s\",\"ordinal\":0,"
            "\"flag_38\":%u,\"flag_50\":%u,\"f32\":",
            (unsigned long)sequence, phase,
            (unsigned long)replay_active_tick, (unsigned long)reset_id,
            (unsigned long)caller_site, particle_type(read_u32(bytes, 0u)),
            (unsigned int)bytes[0x38u], (unsigned int)bytes[0x50u]) ||
        !append_particle_f32_values(line, sizeof(line), &size, bytes) ||
        !particle_line_append(line, sizeof(line), &size,
                              ",\"thread_id\":%lu}\r\n",
                              (unsigned long)GetCurrentThreadId())) return;
    append_record(line, (DWORD)size);
}

static void emit_particle_tick_snapshot(const char *phase,
                                        DWORD emitter_address,
                                        DWORD dt_f32_bits,
                                        DWORD call_id)
{
    BYTE emitter[0x1a0u];
    char line[TRACE_LINE_SIZE];
    DWORD child_array, child_count, index, transform_index, sequence;
    int size = 0;
    if (session_state != SESSION_READY || replay_active_tick == INVALID_ID ||
        copy_readable((const void *)(ULONG_PTR)emitter_address,
                      emitter, sizeof(emitter)) != sizeof(emitter)) return;
    child_array = read_u32(emitter, 0x17cu);
    child_count = read_u32(emitter, 0x180u);
    sequence = next_id(&particle_sequence_number);
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-particle-lifecycle\","
            "\"sequence\":%lu,\"phase\":\"%s\",\"tick\":%lu,"
            "\"call_id\":%lu,\"dt_f32_bits\":\"0x%08lx\","
            "\"type\":\"%s\",\"ordinal\":0,\"child_count\":%lu,"
            "\"child_array_present\":%s,\"source_present\":%s,"
            "\"flag_38\":%u,\"flag_50\":%u,"
            "\"phase_f32_bits\":\"0x%08lx\","
            "\"source_f32_bits\":\"0x%08lx\","
            "\"audio_f32_bits\":\"0x%08lx\",\"f32\":",
            (unsigned long)sequence, phase,
            (unsigned long)replay_active_tick, (unsigned long)call_id,
            (unsigned long)dt_f32_bits,
            particle_type(read_u32(emitter, 0u)),
            (unsigned long)child_count, child_array ? "true" : "false",
            read_u32(emitter, 0x178u) ? "true" : "false",
            (unsigned int)emitter[0x38u], (unsigned int)emitter[0x50u],
            (unsigned long)read_u32(emitter, 0x184u),
            (unsigned long)read_u32(emitter, 0x188u),
            (unsigned long)read_u32(emitter, 0x19cu)) ||
        !append_particle_f32_values(line, sizeof(line), &size, emitter) ||
        !append_particle_render_f32_values(
            line, sizeof(line), &size, emitter) ||
        !particle_line_append(line, sizeof(line), &size,
                              ",\"position_f32\":[")) return;
    for (transform_index = 0u; transform_index < 3u; ++transform_index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                transform_index == 0u ? "" : ",",
                (unsigned long)read_u32(
                    emitter, 0x104u + transform_index * 4u))) return;
    }
    if (!particle_line_append(line, sizeof(line), &size,
                              "],\"thread_id\":%lu}\r\n",
                              (unsigned long)GetCurrentThreadId())) return;
    append_record(line, (DWORD)size);

    if (child_count > MAX_PARTICLE_CHILDREN ||
        (child_count != 0u && child_array == 0u)) {
        session_fail("particle_child_array_contract");
        return;
    }
    for (index = 0u; index < child_count; ++index) {
        BYTE child[0x58u];
        size = 0;
        if (copy_readable(
                (const void *)(ULONG_PTR)(child_array + index * sizeof(child)),
                child, sizeof(child)) != sizeof(child)) {
            session_fail("particle_child_snapshot_contract");
            return;
        }
        sequence = next_id(&particle_sequence_number);
        if (!particle_line_append(
                line, sizeof(line), &size,
                "MVD {\"schema\":1,"
                "\"protocol\":\"miel-vliegt-native-particle-lifecycle\","
                "\"sequence\":%lu,\"phase\":\"%s\",\"tick\":%lu,"
                "\"call_id\":%lu,\"dt_f32_bits\":\"0x%08lx\","
                "\"type\":\"%s\",\"ordinal\":%lu,"
                "\"flag_38\":%u,\"flag_50\":%u,\"f32\":",
                (unsigned long)sequence, phase,
                (unsigned long)replay_active_tick, (unsigned long)call_id,
                (unsigned long)dt_f32_bits,
                particle_type(read_u32(child, 0u)),
                (unsigned long)(index + 1u),
                (unsigned int)child[0x38u], (unsigned int)child[0x50u]) ||
            !append_particle_f32_values(line, sizeof(line), &size, child) ||
            !append_particle_render_f32_values(
                line, sizeof(line), &size, child) ||
            !particle_line_append(line, sizeof(line), &size,
                                  ",\"thread_id\":%lu}\r\n",
                                  (unsigned long)GetCurrentThreadId())) return;
        append_record(line, (DWORD)size);
    }
}

static BOOL particle_activation_enabled(void)
{
    return InterlockedCompareExchange(
        &particle_activation_epoch_open, 0, 0) == 1 &&
        session_state != SESSION_READY;
}

static void emit_particle_activation_object_snapshot(
    const char *phase, DWORD object_address, DWORD caller_site,
    DWORD event_id)
{
    BYTE bytes[0x58u];
    char line[TRACE_LINE_SIZE];
    DWORD sequence;
    int size = 0;
    if (!particle_activation_enabled() ||
        copy_readable((const void *)(ULONG_PTR)object_address,
                      bytes, sizeof(bytes)) != sizeof(bytes)) return;
    sequence = next_id(&particle_activation_sequence_number);
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-particle-activation\","
            "\"sequence\":%lu,\"phase\":\"%s\","
            "\"manager_tick\":%lu,\"event_id\":%lu,"
            "\"caller_site\":\"0x%08lx\",\"type\":\"%s\","
            "\"ordinal\":0,\"flag_38\":%u,\"flag_50\":%u,\"f32\":",
            (unsigned long)sequence, phase,
            (unsigned long)InterlockedCompareExchange(
                &manager_tick_count, 0, 0),
            (unsigned long)event_id, (unsigned long)caller_site,
            particle_type(read_u32(bytes, 0u)),
            (unsigned int)bytes[0x38u], (unsigned int)bytes[0x50u]) ||
        !append_particle_f32_values(line, sizeof(line), &size, bytes) ||
        !particle_line_append(line, sizeof(line), &size,
                              ",\"thread_id\":%lu}\r\n",
                              (unsigned long)GetCurrentThreadId())) return;
    append_record(line, (DWORD)size);
}

static void emit_particle_activation_emitter_snapshot(
    const char *phase, DWORD emitter_address, DWORD caller_site,
    DWORD dt_f32_bits, DWORD input_vector_address, DWORD event_id)
{
    BYTE emitter[0x1a0u];
    BYTE input[12u] = {0};
    char line[TRACE_LINE_SIZE];
    DWORD child_array, child_count, index, transform_index, sequence;
    BOOL input_present = input_vector_address != 0u &&
        copy_readable((const void *)(ULONG_PTR)input_vector_address,
                      input, sizeof(input)) == sizeof(input);
    if (!particle_activation_enabled() ||
        copy_readable((const void *)(ULONG_PTR)emitter_address,
                      emitter, sizeof(emitter)) != sizeof(emitter)) return;
    child_array = read_u32(emitter, 0x17cu);
    child_count = read_u32(emitter, 0x180u);
    if (child_count > MAX_PARTICLE_CHILDREN ||
        (child_count != 0u && child_array == 0u)) {
        session_fail("particle_activation_child_array_contract");
        return;
    }
    for (index = 0u; index <= child_count; ++index) {
        BYTE child[0x58u];
        const BYTE *bytes = emitter;
        int size = 0;
        if (index != 0u) {
            if (copy_readable(
                    (const void *)(ULONG_PTR)(child_array +
                                              (index - 1u) * sizeof(child)),
                    child, sizeof(child)) != sizeof(child)) {
                session_fail("particle_activation_child_snapshot_contract");
                return;
            }
            bytes = child;
        }
        sequence = next_id(&particle_activation_sequence_number);
        if (!particle_line_append(
                line, sizeof(line), &size,
                "MVD {\"schema\":1,"
                "\"protocol\":\"miel-vliegt-native-particle-activation\","
                "\"sequence\":%lu,\"phase\":\"%s\","
                "\"manager_tick\":%lu,\"event_id\":%lu,"
                "\"caller_site\":\"0x%08lx\","
                "\"dt_f32_bits\":\"0x%08lx\","
                "\"input_present\":%s,\"input_f32\":["
                "\"0x%08lx\",\"0x%08lx\",\"0x%08lx\"],"
                "\"type\":\"%s\",\"ordinal\":%lu,"
                "\"flag_38\":%u,\"flag_50\":%u,\"f32\":",
                (unsigned long)sequence, phase,
                (unsigned long)InterlockedCompareExchange(
                    &manager_tick_count, 0, 0),
                (unsigned long)event_id, (unsigned long)caller_site,
                (unsigned long)dt_f32_bits,
                input_present ? "true" : "false",
                (unsigned long)read_u32(input, 0u),
                (unsigned long)read_u32(input, 4u),
                (unsigned long)read_u32(input, 8u),
                particle_type(read_u32(bytes, 0u)), (unsigned long)index,
                (unsigned int)bytes[0x38u], (unsigned int)bytes[0x50u]) ||
            !append_particle_f32_values(line, sizeof(line), &size, bytes)) {
            return;
        }
        if (index == 0u) {
            if (!particle_line_append(
                    line, sizeof(line), &size,
                    ",\"child_count\":%lu,\"position_f32\":[",
                    (unsigned long)child_count)) return;
            for (transform_index = 0u; transform_index < 3u;
                 ++transform_index) {
                if (!particle_line_append(
                        line, sizeof(line), &size, "%s\"0x%08lx\"",
                        transform_index == 0u ? "" : ",",
                        (unsigned long)read_u32(
                            emitter, 0x104u + transform_index * 4u))) return;
            }
            if (!particle_line_append(line, sizeof(line), &size, "]")) return;
        }
        if (!particle_line_append(line, sizeof(line), &size,
                                  ",\"thread_id\":%lu}\r\n",
                                  (unsigned long)GetCurrentThreadId())) return;
        append_record(line, (DWORD)size);
    }
}

static void __attribute__((used)) particle_tick_before(
    DWORD emitter_address, DWORD dt_f32_bits, DWORD caller_return)
{
    DWORD last_error = GetLastError();
    if (particle_activation_enabled()) {
        particle_active_activation_tick =
            next_id(&particle_activation_call_number);
        emit_particle_activation_emitter_snapshot(
            "TICK_BEFORE", emitter_address,
            caller_return >= 5u ? caller_return - 5u : 0u,
            dt_f32_bits, 0u, particle_active_activation_tick);
    } else if (session_state == SESSION_READY) {
        particle_active_tick_call = next_id(&particle_tick_call_number);
        emit_particle_tick_snapshot("TICK_BEFORE", emitter_address,
                                    dt_f32_bits, particle_active_tick_call);
    }
    SetLastError(last_error);
}

static void __attribute__((used)) particle_tick_after(
    DWORD emitter_address, DWORD dt_f32_bits, DWORD caller_return)
{
    DWORD last_error = GetLastError();
    if (particle_active_activation_tick != INVALID_ID) {
        emit_particle_activation_emitter_snapshot(
            "TICK_AFTER", emitter_address,
            caller_return >= 5u ? caller_return - 5u : 0u,
            dt_f32_bits, 0u, particle_active_activation_tick);
        particle_active_activation_tick = INVALID_ID;
    } else if (particle_active_tick_call != INVALID_ID) {
        emit_particle_tick_snapshot("TICK_AFTER", emitter_address,
                                    dt_f32_bits, particle_active_tick_call);
        particle_active_tick_call = INVALID_ID;
    }
    SetLastError(last_error);
}

static void __attribute__((used)) particle_reset_before(
    DWORD object_address, DWORD caller_return)
{
    DWORD last_error = GetLastError();
    if (particle_activation_enabled()) {
        particle_active_activation_reset =
            next_id(&particle_activation_reset_number);
        emit_particle_activation_object_snapshot(
            "RESET_BEFORE", object_address,
            caller_return >= 5u ? caller_return - 5u : 0u,
            particle_active_activation_reset);
    } else if (session_state == SESSION_READY) {
        particle_active_reset = next_id(&particle_reset_number);
        emit_particle_reset_snapshot(
            "RESET_BEFORE", object_address,
            caller_return >= 5u ? caller_return - 5u : 0u,
            particle_active_reset);
    }
    SetLastError(last_error);
}

static void __attribute__((used)) particle_reset_after(
    DWORD object_address, DWORD caller_return)
{
    DWORD last_error = GetLastError();
    if (particle_active_activation_reset != INVALID_ID) {
        emit_particle_activation_object_snapshot(
            "RESET_AFTER", object_address,
            caller_return >= 5u ? caller_return - 5u : 0u,
            particle_active_activation_reset);
        particle_active_activation_reset = INVALID_ID;
    } else if (particle_active_reset != INVALID_ID) {
        emit_particle_reset_snapshot(
            "RESET_AFTER", object_address,
            caller_return >= 5u ? caller_return - 5u : 0u,
            particle_active_reset);
        particle_active_reset = INVALID_ID;
    }
    SetLastError(last_error);
}

static void __attribute__((used)) particle_place_before(
    DWORD emitter_address, DWORD vector_address, DWORD caller_return)
{
    DWORD last_error = GetLastError();
    if (particle_activation_enabled()) {
        particle_active_activation_place =
            next_id(&particle_activation_call_number);
        emit_particle_activation_emitter_snapshot(
            "PLACE_BEFORE", emitter_address,
            caller_return >= 5u ? caller_return - 5u : 0u,
            0u, vector_address, particle_active_activation_place);
    }
    SetLastError(last_error);
}

static void __attribute__((used)) particle_place_after(
    DWORD emitter_address, DWORD vector_address, DWORD caller_return)
{
    DWORD last_error = GetLastError();
    if (particle_active_activation_place != INVALID_ID) {
        emit_particle_activation_emitter_snapshot(
            "PLACE_AFTER", emitter_address,
            caller_return >= 5u ? caller_return - 5u : 0u,
            0u, vector_address, particle_active_activation_place);
        particle_active_activation_place = INVALID_ID;
    }
    SetLastError(last_error);
}

static void __attribute__((naked)) particle_emitter_tick_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\tpushl %ebp\n\tmovl %ecx, %esi\n\t"
        "movl 16(%esp), %edi\n\tmovl 12(%esp), %ebp\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $4, %esp\n\tpushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _particle_tick_before\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "pushl %edi\n\tmovl %esi, %ecx\n\t"
        "call *_particle_emitter_tick_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $4, %esp\n\tpushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _particle_tick_after\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %ebp\n\tpopl %edi\n\tpopl %esi\n\tret $4\n\t");
}

static void __attribute__((naked)) particle_reset_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\tmovl %ecx, %esi\n\t"
        "movl 8(%esp), %edi\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $8, %esp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _particle_reset_before\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "movl %esi, %ecx\n\tcall *_particle_reset_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $8, %esp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _particle_reset_after\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %edi\n\tpopl %esi\n\tret\n\t");
}

static void __attribute__((naked)) particle_place_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\tpushl %ebp\n\tmovl %ecx, %esi\n\t"
        "movl 16(%esp), %edi\n\tmovl 12(%esp), %ebp\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $4, %esp\n\tpushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _particle_place_before\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "pushl %edi\n\tmovl %esi, %ecx\n\t"
        "call *_particle_place_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $4, %esp\n\tpushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _particle_place_after\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %ebp\n\tpopl %edi\n\tpopl %esi\n\tret $4\n\t");
}

static const DWORD AIRPLANE_TRACK_A_F32_OFFSETS[] = {
    0x94u, 0x98u, 0x9cu, 0xd0u, 0xd4u, 0xd8u
};
static const DWORD AIRPLANE_TRACK_B_F32_OFFSETS[] = {
    0x70u, 0x74u, 0x78u, 0xb8u, 0xbcu, 0xc0u, 0xc4u
};

typedef struct RenderListNodeIdentity {
    DWORD vtable;
    DWORD visible_method;
    DWORD prepare_method;
    DWORD phase_method;
    DWORD draw_method;
} RenderListNodeIdentity;

static BOOL presentation_context_enabled(void)
{
    return session_state == SESSION_READY &&
        replay_active_tick != INVALID_ID &&
        InterlockedCompareExchange(&manager_render_active, 0, 0) == 1;
}

static BOOL presentation_emission_enabled(void)
{
    return !semantic_observation_only && presentation_context_enabled();
}

static BOOL stable_module_identity(DWORD address, char *output,
                                   size_t capacity)
{
    MEMORY_BASIC_INFORMATION information;
    char path[MAX_PATH * 2];
    char *name;
    DWORD length, index, rva;
    int written;
    if (address == 0u || !output || capacity == 0u ||
        VirtualQuery((const void *)(ULONG_PTR)address, &information,
                     sizeof(information)) != sizeof(information) ||
        information.Type != MEM_IMAGE || !information.AllocationBase) {
        return FALSE;
    }
    length = GetModuleFileNameA(
        (HMODULE)information.AllocationBase, path, sizeof(path));
    if (length == 0u || length >= sizeof(path)) return FALSE;
    name = path;
    for (index = 0u; index < length; ++index) {
        if (path[index] == '\\' || path[index] == '/') name = path + index + 1u;
    }
    if (*name == '\0') return FALSE;
    for (index = 0u; name[index] != '\0'; ++index) {
        unsigned char value = (unsigned char)name[index];
        if (value >= 'A' && value <= 'Z') {
            name[index] = (char)(value - 'A' + 'a');
        } else if (!((value >= 'a' && value <= 'z') ||
                     (value >= '0' && value <= '9') || value == '.' ||
                     value == '_' || value == '-')) {
            return FALSE;
        }
    }
    rva = address - (DWORD)(ULONG_PTR)information.AllocationBase;
    written = snprintf(output, capacity, "%s+0x%08lx", name,
                       (unsigned long)rva);
    return written > 0 && (size_t)written < capacity;
}

static BOOL append_airplane_track(char *line, size_t capacity, int *used,
                                  DWORD object_address,
                                  const DWORD *f32_offsets,
                                  DWORD f32_count, BOOL include_flag_6d)
{
    BYTE bytes[0xdcu] = {0};
    DWORD index;
    BOOL present = object_address != 0u;
    if (present &&
        copy_readable((const void *)(ULONG_PTR)object_address,
                      bytes, sizeof(bytes)) != sizeof(bytes)) return FALSE;
    if (include_flag_6d) {
        if (!particle_line_append(
                line, capacity, used,
                "{\"present\":%s,\"flag_6d\":%u,\"f32\":[",
                present ? "true" : "false",
                present ? (unsigned int)bytes[0x6du] : 0u)) return FALSE;
    } else if (!particle_line_append(
            line, capacity, used, "{\"present\":%s,\"f32\":[",
            present ? "true" : "false")) return FALSE;
    for (index = 0u; index < f32_count; ++index) {
        if (!particle_line_append(
                line, capacity, used, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)(present ? read_u32(
                    bytes, f32_offsets[index]) : 0u))) {
            return FALSE;
        }
    }
    return particle_line_append(line, capacity, used, "]}");
}

static void emit_render_list_snapshot(const char *phase, DWORD list_address,
                                      DWORD position_address,
                                      DWORD dt_f32_bits, DWORD call_id)
{
    RenderListNodeIdentity nodes[MAX_RENDER_LIST_NODES];
    BYTE position[12u] = {0};
    DWORD node_address = 0u, node_count = 0u, index;
    BOOL position_present;
    if (!presentation_emission_enabled()) return;
    position_present = position_address != 0u &&
        copy_readable((const void *)(ULONG_PTR)position_address,
                      position, sizeof(position)) == sizeof(position);
    if (!position_present || !read_pointer(list_address, 0u, &node_address)) {
        session_fail("render_list_input_contract");
        return;
    }
    while (node_address != 0u && node_count < MAX_RENDER_LIST_NODES) {
        BYTE node[8u], vtable[0x20u];
        DWORD vtable_address;
        if (copy_readable((const void *)(ULONG_PTR)node_address,
                          node, sizeof(node)) != sizeof(node)) {
            session_fail("render_list_node_contract");
            return;
        }
        vtable_address = read_u32(node, 0u);
        if (copy_readable((const void *)(ULONG_PTR)vtable_address,
                          vtable, sizeof(vtable)) != sizeof(vtable)) {
            session_fail("render_list_vtable_contract");
            return;
        }
        nodes[node_count].vtable = vtable_address;
        nodes[node_count].visible_method = read_u32(vtable, 0x0cu);
        nodes[node_count].prepare_method = read_u32(vtable, 0x10u);
        nodes[node_count].phase_method = read_u32(vtable, 0x18u);
        nodes[node_count].draw_method = read_u32(vtable, 0x1cu);
        node_address = read_u32(node, 4u);
        ++node_count;
    }
    if (node_address != 0u) {
        session_fail("render_list_node_limit");
        return;
    }
    for (index = 0u; index < node_count; ++index) {
        char line[TRACE_LINE_SIZE];
        char vtable_identity[96], visible_identity[96], prepare_identity[96];
        char phase_identity[96], draw_identity[96];
        DWORD sequence = next_id(&presentation_sequence_number);
        int size = 0;
        if (!stable_module_identity(nodes[index].vtable, vtable_identity,
                                    sizeof(vtable_identity)) ||
            !stable_module_identity(nodes[index].visible_method,
                                    visible_identity,
                                    sizeof(visible_identity)) ||
            !stable_module_identity(nodes[index].prepare_method,
                                    prepare_identity,
                                    sizeof(prepare_identity)) ||
            !stable_module_identity(nodes[index].phase_method, phase_identity,
                                    sizeof(phase_identity)) ||
            !stable_module_identity(nodes[index].draw_method, draw_identity,
                                    sizeof(draw_identity))) {
            session_fail("render_list_identity_contract");
            return;
        }
        if (!particle_line_append(
                line, sizeof(line), &size,
                "MVD {\"schema\":1,"
                "\"protocol\":\"miel-vliegt-native-render-presentation\","
                "\"sequence\":%lu,\"kind\":\"render-list\","
                "\"phase\":\"%s\",\"tick\":%lu,"
                "\"manager_render\":%lu,\"call_id\":%lu,"
                "\"node_count\":%lu,\"ordinal\":%lu,"
                "\"dt_f32_bits\":\"0x%08lx\","
                "\"position_f32\":[\"0x%08lx\",\"0x%08lx\","
                "\"0x%08lx\"],\"vtable\":\"%s\","
                "\"visible_method\":\"%s\","
                "\"prepare_method\":\"%s\","
                "\"phase_method\":\"%s\",\"draw_method\":\"%s\","
                "\"thread_id\":%lu}\r\n",
                (unsigned long)sequence, phase,
                (unsigned long)replay_active_tick,
                (unsigned long)InterlockedCompareExchange(
                    &manager_render_count, 0, 0),
                (unsigned long)call_id, (unsigned long)node_count,
                (unsigned long)index, (unsigned long)dt_f32_bits,
                (unsigned long)read_u32(position, 0u),
                (unsigned long)read_u32(position, 4u),
                (unsigned long)read_u32(position, 8u), vtable_identity,
                visible_identity, prepare_identity, phase_identity,
                draw_identity, (unsigned long)GetCurrentThreadId())) return;
        append_record(line, (DWORD)size);
    }
}

static void emit_airplane_presentation_snapshot(const char *phase,
                                                DWORD airplane_address,
                                                DWORD call_id)
{
    BYTE airplane[0x23cu];
    char line[TRACE_LINE_SIZE], identity[96];
    DWORD sequence;
    int size = 0;
    if (!presentation_emission_enabled()) return;
    if (copy_readable((const void *)(ULONG_PTR)airplane_address,
                      airplane, sizeof(airplane)) != sizeof(airplane) ||
        !stable_module_identity(read_u32(airplane, 0u), identity,
                                sizeof(identity))) {
        session_fail("airplane_presentation_owner_contract");
        return;
    }
    sequence = next_id(&presentation_sequence_number);
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-render-presentation\","
            "\"sequence\":%lu,\"kind\":\"airplane\","
            "\"phase\":\"%s\",\"tick\":%lu,"
            "\"manager_render\":%lu,\"call_id\":%lu,"
            "\"owner_vtable\":\"%s\",\"source_present\":%s,"
            "\"world_present\":%s,\"anchor_f32\":["
            "\"0x%08lx\",\"0x%08lx\",\"0x%08lx\"],"
            "\"track_a\":",
            (unsigned long)sequence, phase,
            (unsigned long)replay_active_tick,
            (unsigned long)InterlockedCompareExchange(
                &manager_render_count, 0, 0),
            (unsigned long)call_id, identity,
            read_u32(airplane, 0x1f4u) ? "true" : "false",
            read_u32(airplane, 0x1fcu) ? "true" : "false",
            (unsigned long)read_u32(airplane, 0x210u),
            (unsigned long)read_u32(airplane, 0x214u),
            (unsigned long)read_u32(airplane, 0x218u)) ||
        !append_airplane_track(
            line, sizeof(line), &size, read_u32(airplane, 0x230u),
            AIRPLANE_TRACK_A_F32_OFFSETS,
            sizeof(AIRPLANE_TRACK_A_F32_OFFSETS) /
                sizeof(AIRPLANE_TRACK_A_F32_OFFSETS[0]), FALSE) ||
        !particle_line_append(line, sizeof(line), &size, ",\"track_b\":") ||
        !append_airplane_track(
            line, sizeof(line), &size, read_u32(airplane, 0x234u),
            AIRPLANE_TRACK_B_F32_OFFSETS,
            sizeof(AIRPLANE_TRACK_B_F32_OFFSETS) /
                sizeof(AIRPLANE_TRACK_B_F32_OFFSETS[0]), TRUE) ||
        !particle_line_append(
            line, sizeof(line), &size, ",\"thread_id\":%lu}\r\n",
            (unsigned long)GetCurrentThreadId())) {
        session_fail("airplane_presentation_track_contract");
        return;
    }
    append_record(line, (DWORD)size);
}

static void __attribute__((used)) render_list_before(
    DWORD list_address, DWORD position_address, DWORD dt_f32_bits)
{
    DWORD last_error = GetLastError();
    if (presentation_context_enabled()) {
        if (active_render_list_call != INVALID_ID) {
            session_fail("render_list_reentrancy_contract");
        } else {
            active_render_list_call = next_id(&render_list_call_number);
            emit_render_list_snapshot("BEFORE", list_address,
                                      position_address, dt_f32_bits,
                                      active_render_list_call);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) render_list_after(
    DWORD list_address, DWORD position_address, DWORD dt_f32_bits)
{
    DWORD last_error = GetLastError();
    if (active_render_list_call != INVALID_ID) {
        emit_render_list_snapshot("AFTER", list_address, position_address,
                                  dt_f32_bits, active_render_list_call);
        active_render_list_call = INVALID_ID;
    }
    SetLastError(last_error);
}

static void __attribute__((used)) airplane_presentation_before(
    DWORD airplane_address)
{
    DWORD last_error = GetLastError();
    if (presentation_context_enabled()) {
        if (active_airplane_presentation_call != INVALID_ID) {
            session_fail("airplane_presentation_reentrancy_contract");
        } else {
            active_airplane_presentation_call =
                next_id(&airplane_presentation_call_number);
            emit_airplane_presentation_snapshot(
                "BEFORE", airplane_address,
                active_airplane_presentation_call);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) airplane_presentation_after(
    DWORD airplane_address)
{
    DWORD last_error = GetLastError();
    if (active_airplane_presentation_call != INVALID_ID) {
        emit_airplane_presentation_snapshot(
            "AFTER", airplane_address, active_airplane_presentation_call);
        active_airplane_presentation_call = INVALID_ID;
    }
    SetLastError(last_error);
}

static void __attribute__((naked)) render_list_dispatch_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\tpushl %ebp\n\tmovl %ecx, %esi\n\t"
        "movl 16(%esp), %edi\n\tmovl 20(%esp), %ebp\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $4, %esp\n\tpushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _render_list_before\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "pushl %ebp\n\tpushl %edi\n\tmovl %esi, %ecx\n\t"
        "call *_render_list_dispatch_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $4, %esp\n\tpushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _render_list_after\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %ebp\n\tpopl %edi\n\tpopl %esi\n\tret $8\n\t");
}

static void __attribute__((naked)) airplane_presentation_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tmovl %ecx, %esi\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $12, %esp\n\tpushl %esi\n\t"
        "call _airplane_presentation_before\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "movl %esi, %ecx\n\tcall *_airplane_presentation_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $12, %esp\n\tpushl %esi\n\t"
        "call _airplane_presentation_after\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %esi\n\tret\n\t");
}

static WORD read_u16(const BYTE *bytes, SIZE_T offset)
{
    WORD value;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static void emit_shadow_render_snapshot(const char *phase,
                                        DWORD shadow_address,
                                        DWORD target_address,
                                        DWORD call_id,
                                        DWORD parent_call_id)
{
    static const DWORD TRANSFORM_OFFSETS[] = {
        0x94u, 0x98u, 0x9cu, 0xd0u, 0xd4u, 0xd8u
    };
    BYTE shadow[0x9f0u], surface[0x8au] = {0};
    char line[TRACE_LINE_SIZE], target_identity[96];
    DWORD sequence, surface_address, index;
    BOOL surface_present;
    int size = 0;
    if (!presentation_emission_enabled()) return;
    if (copy_readable((const void *)(ULONG_PTR)shadow_address,
                      shadow, sizeof(shadow)) != sizeof(shadow) ||
        target_address == 0u ||
        !read_pointer(target_address, 0u, &index) ||
        !stable_module_identity(index, target_identity,
                                sizeof(target_identity))) {
        session_fail("shadow_render_input_contract");
        return;
    }
    surface_address = read_u32(shadow, 0x9e0u);
    surface_present = surface_address != 0u;
    if (surface_present &&
        copy_readable((const void *)(ULONG_PTR)surface_address,
                      surface, sizeof(surface)) != sizeof(surface)) {
        session_fail("shadow_render_surface_contract");
        return;
    }
    sequence = next_id(&shadow_render_sequence_number);
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-shadow-render\","
            "\"sequence\":%lu,\"phase\":\"%s\",\"tick\":%lu,"
            "\"manager_render\":%lu,\"parent_call_id\":%lu,"
            "\"call_id\":%lu,\"target_vtable\":\"%s\","
            "\"surface_present\":%s,\"resource_present\":%s,"
            "\"room_present\":%s,\"surface_active\":%u,"
            "\"render_mode_f32_bits\":\"0x%08lx\","
            "\"transform_f32\":[",
            (unsigned long)sequence, phase,
            (unsigned long)replay_active_tick,
            (unsigned long)InterlockedCompareExchange(
                &manager_render_count, 0, 0),
            (unsigned long)parent_call_id, (unsigned long)call_id,
            target_identity, surface_present ? "true" : "false",
            read_u32(shadow, 0x9e4u) ? "true" : "false",
            read_u32(shadow, 0x9ecu) ? "true" : "false",
            surface_present ? (unsigned int)surface[0x88u] : 0u,
            (unsigned long)read_u32(shadow, 0x9e8u))) return;
    for (index = 0u;
         index < sizeof(TRANSFORM_OFFSETS) / sizeof(TRANSFORM_OFFSETS[0]);
         ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)read_u32(
                    shadow, TRANSFORM_OFFSETS[index]))) return;
    }
    if (!particle_line_append(line, sizeof(line), &size,
                              "],\"mask_u16\":[")) return;
    for (index = 0u; index < 17u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%04x\"",
                index == 0u ? "" : ",",
                surface_present ?
                    (unsigned int)read_u16(surface, 0x68u + index * 2u) : 0u)) {
            return;
        }
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"thread_id\":%lu}\r\n",
            (unsigned long)GetCurrentThreadId())) return;
    append_record(line, (DWORD)size);
}

static void __attribute__((used)) shadow_render_before(
    DWORD shadow_address, DWORD target_address)
{
    DWORD last_error = GetLastError();
    if (presentation_context_enabled()) {
        if (active_shadow_render_call != INVALID_ID ||
            active_airplane_presentation_call == INVALID_ID) {
            session_fail("shadow_render_nesting_contract");
        } else {
            active_shadow_render_call = next_id(&shadow_render_call_number);
            emit_shadow_render_snapshot(
                "BEFORE", shadow_address, target_address,
                active_shadow_render_call,
                active_airplane_presentation_call);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) shadow_render_after(
    DWORD shadow_address, DWORD target_address)
{
    DWORD last_error = GetLastError();
    if (active_shadow_render_call != INVALID_ID) {
        if (active_shadow_camera_call != INVALID_ID) {
            session_fail("shadow_camera_render_unbalanced_contract");
            active_shadow_camera_call = INVALID_ID;
        }
        emit_shadow_render_snapshot(
            "AFTER", shadow_address, target_address,
            active_shadow_render_call,
            active_airplane_presentation_call);
        active_shadow_render_call = INVALID_ID;
    }
    SetLastError(last_error);
}

static void __attribute__((naked)) shadow_render_iat_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\tmovl %ecx, %esi\n\t"
        "movl 12(%esp), %edi\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $8, %esp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_render_before\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "pushl %edi\n\tmovl %esi, %ecx\n\tcall *_shadow_render_original\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $8, %esp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_render_after\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %edi\n\tpopl %esi\n\tret $4\n\t");
}

static void emit_shadow_camera_render_snapshot(const char *phase,
                                               DWORD camera_address,
                                               DWORD render_shadow,
                                               DWORD call_id,
                                               DWORD parent_shadow_call_id)
{
    static const DWORD PROJECTION_F32_OFFSETS[] = {
        0x8fcu, 0x900u, 0x904u, 0x908u, 0x90cu, 0x910u, 0x914u,
        0x918u, 0x924u, 0x928u, 0x92cu, 0x930u, 0x934u, 0x93cu,
        0x940u, 0x944u, 0x948u
    };
    BYTE camera[0x9dcu];
    char line[TRACE_LINE_SIZE], camera_identity[96];
    DWORD sequence, index;
    int size = 0;
    if (!presentation_emission_enabled()) return;
    if (render_shadow > 1u ||
        copy_readable((const void *)(ULONG_PTR)camera_address,
                      camera, sizeof(camera)) != sizeof(camera) ||
        !stable_module_identity(read_u32(camera, 0u), camera_identity,
                                sizeof(camera_identity))) {
        session_fail("shadow_camera_render_input_contract");
        return;
    }
    sequence = next_id(&shadow_camera_render_sequence_number);
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-shadow-camera-render\","
            "\"sequence\":%lu,\"phase\":\"%s\",\"tick\":%lu,"
            "\"manager_render\":%lu,\"parent_shadow_call_id\":%lu,"
            "\"call_id\":%lu,\"render_shadow\":%s,"
            "\"camera_vtable\":\"%s\",\"gate_968\":%u,"
            "\"gate_969\":%u,\"room_present\":%s,"
            "\"device_present\":%s,\"clip_present\":%s,"
            "\"scratch_present\":%s,\"render_flags_u8\":[",
            (unsigned long)sequence, phase,
            (unsigned long)replay_active_tick,
            (unsigned long)InterlockedCompareExchange(
                &manager_render_count, 0, 0),
            (unsigned long)parent_shadow_call_id,
            (unsigned long)call_id,
            render_shadow ? "true" : "false", camera_identity,
            (unsigned int)camera[0x968u], (unsigned int)camera[0x969u],
            read_u32(camera, 0xf4u) ? "true" : "false",
            read_u32(camera, 0xf8u) ? "true" : "false",
            read_u32(camera, 0x94cu) ? "true" : "false",
            read_u32(camera, 0x950u) ? "true" : "false")) return;
    for (index = 0u; index < 4u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s%u",
                index == 0u ? "" : ",",
                (unsigned int)camera[0x91cu + index])) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"projection_f32\":[")) return;
    for (index = 0u;
         index < sizeof(PROJECTION_F32_OFFSETS) /
                     sizeof(PROJECTION_F32_OFFSETS[0]);
         ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)read_u32(
                    camera, PROJECTION_F32_OFFSETS[index]))) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"transform_f32\":[")) return;
    for (index = 0u; index < 14u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)read_u32(camera, 0x58u + index * 4u))) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"saved_transform_f32\":[")) return;
    for (index = 0u; index < 14u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)read_u32(camera, 0x9a4u + index * 4u))) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"thread_id\":%lu}\r\n",
            (unsigned long)GetCurrentThreadId())) return;
    append_record(line, (DWORD)size);
}

static void __attribute__((used)) shadow_camera_render_before(
    DWORD camera_address, DWORD render_shadow)
{
    DWORD last_error = GetLastError();
    if (presentation_context_enabled() &&
        active_shadow_render_call != INVALID_ID) {
        if (active_shadow_camera_call != INVALID_ID) {
            session_fail("shadow_camera_render_nesting_contract");
        } else {
            active_shadow_camera_call = next_id(
                &shadow_camera_render_call_number);
            emit_shadow_camera_render_snapshot(
                "BEFORE", camera_address, render_shadow,
                active_shadow_camera_call, active_shadow_render_call);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) shadow_camera_render_after(
    DWORD camera_address, DWORD render_shadow)
{
    DWORD last_error = GetLastError();
    if (active_shadow_camera_call != INVALID_ID) {
        if (active_shadow_render_room_call != INVALID_ID) {
            session_fail("shadow_render_room_unbalanced_contract");
            active_shadow_render_room_call = INVALID_ID;
        }
        if (active_shadow_render_call == INVALID_ID) {
            session_fail("shadow_camera_render_parent_contract");
        } else {
            emit_shadow_camera_render_snapshot(
                "AFTER", camera_address, render_shadow,
                active_shadow_camera_call, active_shadow_render_call);
        }
        active_shadow_camera_call = INVALID_ID;
    }
    SetLastError(last_error);
}

static void __attribute__((naked)) shadow_camera_render_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\tmovl %ecx, %esi\n\t"
        "movl 12(%esp), %edi\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $8, %esp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_camera_render_before\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "pushl %edi\n\tmovl %esi, %ecx\n\t"
        "call *_shadow_camera_render_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $8, %esp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_camera_render_after\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %edi\n\tpopl %esi\n\tret $4\n\t");
}

static void emit_shadow_render_room_snapshot(const char *phase,
                                             DWORD camera_address,
                                             DWORD room_address,
                                             DWORD clip_address,
                                             DWORD collect_objects,
                                             DWORD recursion_depth,
                                             DWORD call_id,
                                             DWORD parent_camera_call_id)
{
    static const DWORD ROOM_LINK_OFFSETS[] = {
        0x0cu, 0x14u, 0x20u, 0x30u, 0x3cu
    };
    BYTE camera[0x924u], room[0x40u], clip[0x0cu];
    char line[TRACE_LINE_SIZE], camera_identity[96], room_identity[96];
    char clip_identity[96];
    DWORD sequence, index;
    int size = 0;
    if (!presentation_emission_enabled()) return;
    if (camera_address == 0u || room_address == 0u || clip_address == 0u ||
        copy_readable((const void *)(ULONG_PTR)camera_address,
                      camera, sizeof(camera)) != sizeof(camera) ||
        copy_readable((const void *)(ULONG_PTR)room_address,
                      room, sizeof(room)) != sizeof(room) ||
        copy_readable((const void *)(ULONG_PTR)clip_address,
                      clip, sizeof(clip)) != sizeof(clip) ||
        !stable_module_identity(read_u32(camera, 0u), camera_identity,
                                sizeof(camera_identity)) ||
        !stable_module_identity(read_u32(room, 0u), room_identity,
                                sizeof(room_identity)) ||
        !stable_module_identity(read_u32(clip, 0u), clip_identity,
                                sizeof(clip_identity))) {
        session_fail("shadow_render_room_input_contract");
        return;
    }
    sequence = next_id(&shadow_render_room_sequence_number);
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-shadow-render-room\","
            "\"sequence\":%lu,\"phase\":\"%s\",\"tick\":%lu,"
            "\"manager_render\":%lu,\"parent_camera_call_id\":%lu,"
            "\"call_id\":%lu,\"camera_vtable\":\"%s\","
            "\"room_vtable\":\"%s\",\"clip_vtable\":\"%s\","
            "\"collect_objects\":%lu,\"recursion_depth\":%lu,"
            "\"room_links\":[",
            (unsigned long)sequence, phase,
            (unsigned long)replay_active_tick,
            (unsigned long)InterlockedCompareExchange(
                &manager_render_count, 0, 0),
            (unsigned long)parent_camera_call_id, (unsigned long)call_id,
            camera_identity, room_identity, clip_identity,
            (unsigned long)collect_objects, (unsigned long)recursion_depth)) {
        return;
    }
    for (index = 0u;
         index < sizeof(ROOM_LINK_OFFSETS) / sizeof(ROOM_LINK_OFFSETS[0]);
         ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s%s",
                index == 0u ? "" : ",",
                read_u32(room, ROOM_LINK_OFFSETS[index]) ? "true" : "false")) {
            return;
        }
    }
    if (!particle_line_append(
            line, sizeof(line), &size,
            "],\"clip_links\":[%s,%s],"
            "\"camera_transient_present\":%s,\"thread_id\":%lu}\r\n",
            read_u32(clip, 0x04u) ? "true" : "false",
            read_u32(clip, 0x08u) ? "true" : "false",
            read_u32(camera, 0x920u) ? "true" : "false",
            (unsigned long)GetCurrentThreadId())) return;
    append_record(line, (DWORD)size);
}

static void __attribute__((used)) shadow_render_room_before(
    DWORD camera_address, DWORD room_address, DWORD clip_address,
    DWORD collect_objects, DWORD recursion_depth)
{
    DWORD last_error = GetLastError();
    if (presentation_context_enabled() &&
        active_shadow_camera_call != INVALID_ID) {
        if (active_shadow_render_room_call != INVALID_ID) {
            session_fail("shadow_render_room_nesting_contract");
        } else {
            active_shadow_render_room_call = next_id(
                &shadow_render_room_call_number);
            emit_shadow_render_room_snapshot(
                "BEFORE", camera_address, room_address, clip_address,
                collect_objects, recursion_depth,
                active_shadow_render_room_call, active_shadow_camera_call);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) shadow_render_room_after(
    DWORD camera_address, DWORD room_address, DWORD clip_address,
    DWORD collect_objects, DWORD recursion_depth)
{
    DWORD last_error = GetLastError();
    if (active_shadow_render_room_call != INVALID_ID) {
        if (active_shadow_visible_objects_call != INVALID_ID) {
            session_fail("shadow_visible_objects_unbalanced_contract");
            active_shadow_visible_objects_call = INVALID_ID;
        }
        if (active_shadow_visible_polygons_call != INVALID_ID) {
            session_fail("shadow_visible_polygons_unbalanced_contract");
            active_shadow_visible_polygons_call = INVALID_ID;
        }
        if (shadow_world_relation_depth != 0u) {
            session_fail("shadow_world_relation_unbalanced_contract");
            shadow_world_relation_depth = 0u;
        }
        if (active_shadow_camera_call == INVALID_ID) {
            session_fail("shadow_render_room_parent_contract");
        } else {
            emit_shadow_render_room_snapshot(
                "AFTER", camera_address, room_address, clip_address,
                collect_objects, recursion_depth,
                active_shadow_render_room_call, active_shadow_camera_call);
        }
        active_shadow_render_room_call = INVALID_ID;
    }
    SetLastError(last_error);
}

static void __attribute__((naked)) shadow_render_room_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\tpushl %ebp\n\tmovl %ecx, %esi\n\t"
        "movl 16(%esp), %edi\n\tmovl 20(%esp), %ebp\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $12, %esp\n\tpushl 64(%ebx)\n\tpushl 60(%ebx)\n\t"
        "pushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_render_room_before\n\taddl $32, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "pushl 28(%esp)\n\tpushl 28(%esp)\n\tpushl %ebp\n\tpushl %edi\n\t"
        "movl %esi, %ecx\n\tcall *_shadow_render_room_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $12, %esp\n\tpushl 64(%ebx)\n\tpushl 60(%ebx)\n\t"
        "pushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_render_room_after\n\taddl $32, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %ebp\n\tpopl %edi\n\tpopl %esi\n\tret $16\n\t");
}

static BOOL collect_shadow_object_chain(DWORD first_object,
                                        DWORD addresses[MAX_RENDER_LIST_NODES],
                                        DWORD *count_out)
{
    DWORD count = 0u, current = first_object, next, prior;
    while (current != 0u && count < MAX_RENDER_LIST_NODES) {
        for (prior = 0u; prior < count; ++prior) {
            if (addresses[prior] == current) return FALSE;
        }
        addresses[count++] = current;
        if (!read_pointer(current, 0x10cu, &next)) return FALSE;
        current = next;
    }
    if (current != 0u) return FALSE;
    *count_out = count;
    return TRUE;
}

static void emit_shadow_visible_objects_snapshot(const char *phase,
                                                 DWORD room_address,
                                                 DWORD camera_address,
                                                 DWORD render_list_address,
                                                 DWORD first_object,
                                                 DWORD call_id,
                                                 DWORD parent_room_call_id)
{
    static const DWORD OBJECT_FLAG_OFFSETS[] = {
        0x17du, 0x160u, 0x161u, 0x17eu
    };
    static const DWORD GEOMETRY_FLAG_OFFSETS[] = {
        0x112u, 0x111u
    };
    static const DWORD DERIVED_F32_OFFSETS[] = {
        0x44u, 0x4cu, 0x50u, 0x54u, 0x140u, 0x164u, 0x168u
    };
    DWORD addresses[MAX_RENDER_LIST_NODES], count, ordinal, index, sequence;
    BYTE room[4u], camera[0x920u], render_list[44u], object[0x180u];
    BYTE geometry[0x120u];
    char line[TRACE_LINE_SIZE], room_identity[96], camera_identity[96];
    char object_identity[96];
    int size;
    if (!presentation_emission_enabled()) return;
    if (room_address == 0u || camera_address == 0u ||
        render_list_address == 0u ||
        copy_readable((const void *)(ULONG_PTR)room_address,
                      room, sizeof(room)) != sizeof(room) ||
        copy_readable((const void *)(ULONG_PTR)camera_address,
                      camera, sizeof(camera)) != sizeof(camera) ||
        copy_readable((const void *)(ULONG_PTR)render_list_address,
                      render_list, sizeof(render_list)) != sizeof(render_list) ||
        !stable_module_identity(read_u32(room, 0u), room_identity,
                                sizeof(room_identity)) ||
        !stable_module_identity(read_u32(camera, 0u), camera_identity,
                                sizeof(camera_identity)) ||
        !collect_shadow_object_chain(first_object, addresses, &count)) {
        session_fail("shadow_visible_objects_input_contract");
        return;
    }
    sequence = next_id(&shadow_visible_objects_sequence_number);
    size = 0;
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-shadow-visible-objects\","
            "\"sequence\":%lu,\"kind\":\"call\","
            "\"phase\":\"%s\",\"tick\":%lu,\"manager_render\":%lu,"
            "\"parent_room_call_id\":%lu,\"call_id\":%lu,"
            "\"room_vtable\":\"%s\",\"camera_vtable\":\"%s\","
            "\"chain_count\":%lu,\"render_list_present\":[",
            (unsigned long)sequence, phase,
            (unsigned long)replay_active_tick,
            (unsigned long)InterlockedCompareExchange(
                &manager_render_count, 0, 0),
            (unsigned long)parent_room_call_id, (unsigned long)call_id,
            room_identity, camera_identity, (unsigned long)count)) return;
    for (index = 0u; index < 11u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s%s",
                index == 0u ? "" : ",",
                read_u32(render_list, index * 4u) ? "true" : "false")) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"thread_id\":%lu}\r\n",
            (unsigned long)GetCurrentThreadId())) return;
    append_record(line, (DWORD)size);

    for (ordinal = 0u; ordinal < count; ++ordinal) {
        DWORD geometry_address, child_count;
        BOOL geometry_present;
        if (copy_readable((const void *)(ULONG_PTR)addresses[ordinal],
                          object, sizeof(object)) != sizeof(object) ||
            !stable_module_identity(read_u32(object, 0u), object_identity,
                                    sizeof(object_identity))) {
            session_fail("shadow_visible_object_state_contract");
            return;
        }
        geometry_address = read_u32(object, 0x120u);
        geometry_present = geometry_address != 0u;
        memset(geometry, 0, sizeof(geometry));
        if (geometry_present &&
            copy_readable((const void *)(ULONG_PTR)geometry_address,
                          geometry, sizeof(geometry)) != sizeof(geometry)) {
            session_fail("shadow_visible_object_geometry_contract");
            return;
        }
        child_count = read_u32(object, 0x150u);
        sequence = next_id(&shadow_visible_objects_sequence_number);
        size = 0;
        if (!particle_line_append(
                line, sizeof(line), &size,
                "MVD {\"schema\":1,"
                "\"protocol\":\"miel-vliegt-native-shadow-visible-objects\","
                "\"sequence\":%lu,\"kind\":\"object\","
                "\"phase\":\"%s\",\"tick\":%lu,"
                "\"manager_render\":%lu,\"parent_room_call_id\":%lu,"
                "\"call_id\":%lu,\"ordinal\":%lu,\"chain_count\":%lu,"
                "\"object_vtable\":\"%s\",\"flags_u8\":[",
                (unsigned long)sequence, phase,
                (unsigned long)replay_active_tick,
                (unsigned long)InterlockedCompareExchange(
                    &manager_render_count, 0, 0),
                (unsigned long)parent_room_call_id, (unsigned long)call_id,
                (unsigned long)ordinal, (unsigned long)count,
                object_identity)) return;
        for (index = 0u;
             index < sizeof(OBJECT_FLAG_OFFSETS) /
                         sizeof(OBJECT_FLAG_OFFSETS[0]); ++index) {
            if (!particle_line_append(
                    line, sizeof(line), &size, "%s%u",
                    index == 0u ? "" : ",",
                    (unsigned int)object[OBJECT_FLAG_OFFSETS[index]])) return;
        }
        for (index = 0u;
             index < sizeof(GEOMETRY_FLAG_OFFSETS) /
                         sizeof(GEOMETRY_FLAG_OFFSETS[0]); ++index) {
            if (!particle_line_append(
                    line, sizeof(line), &size, ",%u",
                    (unsigned int)geometry[GEOMETRY_FLAG_OFFSETS[index]])) return;
        }
        if (!particle_line_append(
                line, sizeof(line), &size,
                "],\"geometry_present\":%s,"
                "\"relation_matches_camera\":%s,\"mode_u32\":%lu,"
                "\"child_count\":%lu,\"children_array_present\":%s,"
                "\"render_link_present\":%s,"
                "\"geometry_extent_f32\":\"0x%08lx\","
                "\"derived_f32\":[",
                geometry_present ? "true" : "false",
                read_u32(object, 0x14u) == read_u32(camera, 0x1cu) ?
                    "true" : "false",
                (unsigned long)read_u32(object, 0x13cu),
                (unsigned long)child_count,
                read_u32(object, 0x14cu) ? "true" : "false",
                read_u32(object, 0x124u) ? "true" : "false",
                (unsigned long)(geometry_present ?
                    read_u32(geometry, 0x11cu) : 0u))) return;
        for (index = 0u;
             index < sizeof(DERIVED_F32_OFFSETS) /
                         sizeof(DERIVED_F32_OFFSETS[0]);
             ++index) {
            if (!particle_line_append(
                    line, sizeof(line), &size, "%s\"0x%08lx\"",
                    index == 0u ? "" : ",",
                    (unsigned long)read_u32(
                        object, DERIVED_F32_OFFSETS[index]))) return;
        }
        if (!particle_line_append(
                line, sizeof(line), &size, "],\"transform_f32\":[")) return;
        for (index = 0u; index < 14u; ++index) {
            if (!particle_line_append(
                    line, sizeof(line), &size, "%s\"0x%08lx\"",
                    index == 0u ? "" : ",",
                    (unsigned long)read_u32(
                        object, 0x58u + index * 4u))) return;
        }
        if (!particle_line_append(
                line, sizeof(line), &size, "],\"thread_id\":%lu}\r\n",
                (unsigned long)GetCurrentThreadId())) return;
        append_record(line, (DWORD)size);
    }
}

static void __attribute__((used)) shadow_visible_objects_before(
    DWORD room_address, DWORD camera_address, DWORD render_list_address,
    DWORD first_object)
{
    DWORD last_error = GetLastError();
    if (presentation_context_enabled() &&
        active_shadow_render_room_call != INVALID_ID) {
        if (active_shadow_visible_objects_call != INVALID_ID) {
            session_fail("shadow_visible_objects_nesting_contract");
        } else {
            active_shadow_visible_objects_call = next_id(
                &shadow_visible_objects_call_number);
            emit_shadow_visible_objects_snapshot(
                "BEFORE", room_address, camera_address, render_list_address,
                first_object, active_shadow_visible_objects_call,
                active_shadow_render_room_call);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) shadow_visible_objects_after(
    DWORD room_address, DWORD camera_address, DWORD render_list_address,
    DWORD first_object)
{
    DWORD last_error = GetLastError();
    if (active_shadow_visible_objects_call != INVALID_ID) {
        if (active_shadow_render_room_call == INVALID_ID) {
            session_fail("shadow_visible_objects_parent_contract");
        } else {
            emit_shadow_visible_objects_snapshot(
                "AFTER", room_address, camera_address, render_list_address,
                first_object, active_shadow_visible_objects_call,
                active_shadow_render_room_call);
        }
        active_shadow_visible_objects_call = INVALID_ID;
    }
    SetLastError(last_error);
}

static void __attribute__((naked)) shadow_visible_objects_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\tpushl %ebp\n\tmovl %ecx, %esi\n\t"
        "movl 16(%esp), %edi\n\tmovl 20(%esp), %ebp\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "pushl 60(%ebx)\n\tpushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_visible_objects_before\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "pushl 24(%esp)\n\tpushl %ebp\n\tpushl %edi\n\t"
        "movl %esi, %ecx\n\tcall *_shadow_visible_objects_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "pushl 60(%ebx)\n\tpushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_visible_objects_after\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %ebp\n\tpopl %edi\n\tpopl %esi\n\tret $12\n\t");
}

static void emit_shadow_visible_polygons_snapshot(
    const char *phase, DWORD object_address, DWORD camera_address,
    DWORD render_list_address, DWORD outline_enabled, DWORD call_id,
    DWORD parent_room_call_id, BOOL compare_render_heads)
{
    DWORD index, sequence, geometry_address, polygon_count;
    BYTE object[0x180u], camera[0x920u], render_list[44u];
    BYTE geometry[0x12cu];
    char line[TRACE_LINE_SIZE], object_identity[96], camera_identity[96];
    int size = 0;
    if (!presentation_emission_enabled()) return;
    if (object_address == 0u || camera_address == 0u ||
        render_list_address == 0u ||
        copy_readable((const void *)(ULONG_PTR)object_address,
                      object, sizeof(object)) != sizeof(object) ||
        copy_readable((const void *)(ULONG_PTR)camera_address,
                      camera, sizeof(camera)) != sizeof(camera) ||
        copy_readable((const void *)(ULONG_PTR)render_list_address,
                      render_list, sizeof(render_list)) != sizeof(render_list) ||
        !stable_module_identity(read_u32(object, 0u), object_identity,
                                sizeof(object_identity)) ||
        !stable_module_identity(read_u32(camera, 0u), camera_identity,
                                sizeof(camera_identity))) {
        session_fail("shadow_visible_polygons_input_contract");
        return;
    }
    geometry_address = read_u32(object, 0x120u);
    memset(geometry, 0, sizeof(geometry));
    if (geometry_address != 0u &&
        copy_readable((const void *)(ULONG_PTR)geometry_address,
                      geometry, sizeof(geometry)) != sizeof(geometry)) {
        session_fail("shadow_visible_polygons_geometry_contract");
        return;
    }
    polygon_count = geometry_address != 0u ? read_u32(geometry, 0x120u) : 0u;
    if (polygon_count > 65535u) {
        session_fail("shadow_visible_polygons_count_contract");
        return;
    }
    sequence = next_id(&shadow_visible_polygons_sequence_number);
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-shadow-visible-polygons\","
            "\"sequence\":%lu,\"phase\":\"%s\",\"tick\":%lu,"
            "\"manager_render\":%lu,\"parent_room_call_id\":%lu,"
            "\"call_id\":%lu,\"object_vtable\":\"%s\","
            "\"camera_vtable\":\"%s\",\"outline_enabled\":%s,"
            "\"object_outline_u8\":%u,"
            "\"object_outline_f32\":\"0x%08lx\","
            "\"camera_mirror_u8\":%u,\"geometry_present\":%s,"
            "\"topology_present\":%s,\"polygon_count\":%lu,"
            "\"transform_f32\":[",
            (unsigned long)sequence, phase,
            (unsigned long)replay_active_tick,
            (unsigned long)InterlockedCompareExchange(
                &manager_render_count, 0, 0),
            (unsigned long)parent_room_call_id, (unsigned long)call_id,
            object_identity, camera_identity,
            outline_enabled ? "true" : "false",
            (unsigned int)object[0x158u],
            (unsigned long)read_u32(object, 0x15cu),
            (unsigned int)camera[0x91cu],
            geometry_address ? "true" : "false",
            geometry_address && read_u32(geometry, 0x128u) ? "true" : "false",
            (unsigned long)polygon_count)) return;
    for (index = 0u; index < 14u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)read_u32(object, 0x58u + index * 4u))) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"render_list_present\":[")) return;
    for (index = 0u; index < 11u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s%s",
                index == 0u ? "" : ",",
                read_u32(render_list, index * 4u) ? "true" : "false")) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"render_list_head_changed\":[")) return;
    for (index = 0u; index < 11u; ++index) {
        BOOL changed = compare_render_heads &&
            read_u32(render_list, index * 4u) !=
                shadow_visible_polygons_render_heads[index];
        if (!particle_line_append(
                line, sizeof(line), &size, "%s%s",
                index == 0u ? "" : ",", changed ? "true" : "false")) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"thread_id\":%lu}\r\n",
            (unsigned long)GetCurrentThreadId())) return;
    append_record(line, (DWORD)size);
}

static void __attribute__((used)) shadow_visible_polygons_before(
    DWORD object_address, DWORD camera_address, DWORD render_list_address,
    DWORD outline_enabled)
{
    DWORD index, last_error = GetLastError();
    BYTE render_list[44u];
    if (presentation_context_enabled() &&
        active_shadow_render_room_call != INVALID_ID) {
        if (active_shadow_visible_polygons_call != INVALID_ID) {
            session_fail("shadow_visible_polygons_nesting_contract");
        } else if (copy_readable(
                (const void *)(ULONG_PTR)render_list_address,
                render_list, sizeof(render_list)) != sizeof(render_list)) {
            session_fail("shadow_visible_polygons_render_list_contract");
        } else {
            for (index = 0u; index < 11u; ++index) {
                shadow_visible_polygons_render_heads[index] =
                    read_u32(render_list, index * 4u);
            }
            shadow_visible_polygons_object = object_address;
            shadow_visible_polygons_camera = camera_address;
            shadow_visible_polygons_render_list = render_list_address;
            shadow_visible_polygons_outline = outline_enabled;
            active_shadow_visible_polygons_call = next_id(
                &shadow_visible_polygons_call_number);
            emit_shadow_visible_polygons_snapshot(
                "BEFORE", object_address, camera_address, render_list_address,
                outline_enabled, active_shadow_visible_polygons_call,
                active_shadow_render_room_call, FALSE);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) shadow_visible_polygons_after(
    DWORD object_address, DWORD camera_address, DWORD render_list_address,
    DWORD outline_enabled)
{
    DWORD last_error = GetLastError();
    if (active_shadow_visible_polygons_call != INVALID_ID) {
        if (active_shadow_render_room_call == INVALID_ID ||
            object_address != shadow_visible_polygons_object ||
            camera_address != shadow_visible_polygons_camera ||
            render_list_address != shadow_visible_polygons_render_list ||
            outline_enabled != shadow_visible_polygons_outline) {
            session_fail("shadow_visible_polygons_parent_contract");
        } else {
            emit_shadow_visible_polygons_snapshot(
                "AFTER", object_address, camera_address, render_list_address,
                outline_enabled, active_shadow_visible_polygons_call,
                active_shadow_render_room_call, TRUE);
        }
        active_shadow_visible_polygons_call = INVALID_ID;
    }
    SetLastError(last_error);
}

static void __attribute__((naked)) shadow_visible_polygons_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\tpushl %ebp\n\tmovl %ecx, %esi\n\t"
        "movl 16(%esp), %edi\n\tmovl 20(%esp), %ebp\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "pushl 60(%ebx)\n\tpushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_visible_polygons_before\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "pushl 24(%esp)\n\tpushl %ebp\n\tpushl %edi\n\t"
        "movl %esi, %ecx\n\tcall *_shadow_visible_polygons_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "pushl 60(%ebx)\n\tpushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_visible_polygons_after\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %ebp\n\tpopl %edi\n\tpopl %esi\n\tret $12\n\t");
}

static void emit_shadow_polygon_render_snapshot(
    DWORD polygon_address, DWORD camera_address, DWORD mode,
    DWORD call_id, DWORD parent_room_call_id)
{
    DWORD object_address, mesh_address, material_address, vertices_address;
    DWORD vertex_addresses[3u], vertex_indices[3u], material_f32[7u];
    DWORD index, component, sequence;
    BYTE polygon[0x14u], object[0x180u], camera[0x92cu], material[0x68u];
    BYTE mesh[0x18u], vertices[3u][0x18u];
    char line[TRACE_LINE_SIZE], polygon_identity[96], object_identity[96];
    char camera_identity[96];
    int size = 0;
    if (!presentation_emission_enabled()) return;
    if (polygon_address == 0u || camera_address == 0u ||
        copy_readable((const void *)(ULONG_PTR)polygon_address,
                      polygon, sizeof(polygon)) != sizeof(polygon) ||
        copy_readable((const void *)(ULONG_PTR)camera_address,
                      camera, sizeof(camera)) != sizeof(camera) ||
        !stable_module_identity(read_u32(polygon, 0u), polygon_identity,
                                sizeof(polygon_identity)) ||
        !stable_module_identity(read_u32(camera, 0u), camera_identity,
                                sizeof(camera_identity))) {
        session_fail("shadow_polygon_render_input_contract");
        return;
    }
    object_address = read_u32(polygon, 0x0cu);
    mesh_address = read_u32(polygon, 0x10u);
    if (object_address == 0u || mesh_address == 0u ||
        copy_readable((const void *)(ULONG_PTR)object_address,
                      object, sizeof(object)) != sizeof(object) ||
        copy_readable((const void *)(ULONG_PTR)mesh_address,
                      mesh, sizeof(mesh)) != sizeof(mesh) ||
        !stable_module_identity(read_u32(object, 0u), object_identity,
                                sizeof(object_identity))) {
        session_fail("shadow_polygon_render_owner_contract");
        return;
    }
    material_address = read_u32(mesh, 0x14u);
    if (material_address != 0u &&
        copy_readable((const void *)(ULONG_PTR)material_address,
                      material, sizeof(material)) != sizeof(material)) {
        session_fail("shadow_polygon_render_material_contract");
        return;
    }
    memset(material_f32, 0, sizeof(material_f32));
    if (material_address != 0u) {
        for (index = 0u; index < 7u; ++index) {
            material_f32[index] = read_u32(material, 0x3cu + index * 4u);
        }
    }
    vertices_address = read_u32(object, 0x144u);
    for (index = 0u; index < 3u; ++index) {
        vertex_indices[index] = read_u32(mesh, 0x08u + index * 4u);
        if (vertex_indices[index] > 65535u || vertices_address == 0u ||
            !read_pointer(vertices_address, vertex_indices[index] * 4u,
                          &vertex_addresses[index]) ||
            vertex_addresses[index] == 0u ||
            copy_readable((const void *)(ULONG_PTR)vertex_addresses[index],
                          vertices[index], sizeof(vertices[index])) !=
                sizeof(vertices[index])) {
            session_fail("shadow_polygon_render_vertex_contract");
            return;
        }
    }
    sequence = next_id(&shadow_polygon_render_sequence_number);
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-shadow-polygon-render\","
            "\"sequence\":%lu,\"tick\":%lu,\"manager_render\":%lu,"
            "\"parent_room_call_id\":%lu,\"call_id\":%lu,"
            "\"polygon_vtable\":\"%s\",\"object_vtable\":\"%s\","
            "\"camera_vtable\":\"%s\","
            "\"material_type\":\"%s\",\"material_flags_u8\":%u,"
            "\"mode_u32\":%lu,"
            "\"material_present\":%s,\"camera_mirror_u8\":%u,"
            "\"camera_projection_f32\":\"0x%08lx\","
            "\"vertex_indices\":[%lu,%lu,%lu],",
            (unsigned long)sequence,
            (unsigned long)replay_active_tick,
            (unsigned long)InterlockedCompareExchange(
                &manager_render_count, 0, 0),
            (unsigned long)parent_room_call_id, (unsigned long)call_id,
            polygon_identity, object_identity, camera_identity,
            material_address ? "CcMaterial" : "none",
            (unsigned int)(material_address ? material[0u] : 0u),
            (unsigned long)mode,
            read_u32(mesh, 0x14u) ? "true" : "false",
            (unsigned int)camera[0x91cu],
            (unsigned long)read_u32(camera, 0x928u),
            (unsigned long)vertex_indices[0u],
            (unsigned long)vertex_indices[1u],
            (unsigned long)vertex_indices[2u])) return;
    if (!particle_line_append(
            line, sizeof(line), &size, "\"material_f32\":[")) return;
    for (index = 0u; index < 7u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)material_f32[index])) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"owner_transform_f32\":[")) return;
    for (index = 0u; index < 14u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)read_u32(object, 0x58u + index * 4u))) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"vertex_f32\":[")) return;
    for (index = 0u; index < 3u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s[",
                index == 0u ? "" : ",")) return;
        for (component = 0u; component < 4u; ++component) {
            if (!particle_line_append(
                    line, sizeof(line), &size, "%s\"0x%08lx\"",
                    component == 0u ? "" : ",",
                    (unsigned long)read_u32(
                        vertices[index], component * 4u))) return;
        }
        if (!particle_line_append(line, sizeof(line), &size, "]")) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size,
            "],\"vertex_cache_u8\":[%u,%u,%u],\"thread_id\":%lu}\r\n",
            (unsigned int)vertices[0u][0x14u],
            (unsigned int)vertices[1u][0x14u],
            (unsigned int)vertices[2u][0x14u],
            (unsigned long)GetCurrentThreadId())) return;
    append_record(line, (DWORD)size);
}

static void __attribute__((used)) shadow_polygon_render_before(
    DWORD polygon_address, DWORD camera_address, DWORD mode)
{
    DWORD last_error = GetLastError();
    if (presentation_context_enabled() &&
        active_shadow_render_room_call != INVALID_ID) {
        DWORD call_id = next_id(&shadow_polygon_render_call_number);
        emit_shadow_polygon_render_snapshot(
            polygon_address, camera_address, mode, call_id,
            active_shadow_render_room_call);
    }
    SetLastError(last_error);
}

static void __attribute__((naked)) shadow_polygon_render_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\tmovl %ecx, %esi\n\t"
        "movl 12(%esp), %edi\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "pushl 52(%ebx)\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_polygon_render_before\n\taddl $12, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "pushl 16(%esp)\n\tpushl %edi\n\t"
        "movl %esi, %ecx\n\tcall *_shadow_polygon_render_trampoline\n\t"
        "popl %edi\n\tpopl %esi\n\tret $8\n\t");
}

static void emit_shadow_world_relation_snapshot(
    const char *phase, DWORD node_address, DWORD return_u8, DWORD call_id,
    DWORD parent_world_call_id, DWORD depth, DWORD parent_room_call_id)
{
    DWORD parent_address, geometry_address, index, sequence;
    BYTE node[0x180u], related[4u], geometry[0x124u];
    char line[TRACE_LINE_SIZE], node_identity[96], parent_identity[96];
    char geometry_identity[96];
    int size = 0;
    if (!presentation_emission_enabled()) return;
    if (node_address == 0u ||
        copy_readable((const void *)(ULONG_PTR)node_address,
                      node, sizeof(node)) != sizeof(node) ||
        !stable_module_identity(read_u32(node, 0u), node_identity,
                                sizeof(node_identity))) {
        session_fail("shadow_world_relation_input_contract");
        return;
    }
    parent_address = read_u32(node, 0x04u);
    geometry_address = strcmp(node_identity, "cc.dll+0x000535e4") == 0 ?
        read_u32(node, 0x120u) : 0u;
    memcpy(parent_identity, "none", 5u);
    memcpy(geometry_identity, "none", 5u);
    memset(geometry, 0, sizeof(geometry));
    if (parent_address != 0u &&
        (copy_readable((const void *)(ULONG_PTR)parent_address,
                       related, sizeof(related)) != sizeof(related) ||
         !stable_module_identity(read_u32(related, 0u), parent_identity,
                                 sizeof(parent_identity)))) {
        session_fail("shadow_world_relation_parent_identity_contract");
        return;
    }
    if (geometry_address != 0u &&
        (copy_readable((const void *)(ULONG_PTR)geometry_address,
                       geometry, sizeof(geometry)) != sizeof(geometry) ||
         !stable_module_identity(read_u32(geometry, 0u), geometry_identity,
                                 sizeof(geometry_identity)))) {
        session_fail("shadow_world_relation_geometry_identity_contract");
        return;
    }
    sequence = next_id(&shadow_world_relation_sequence_number);
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-shadow-world-relation\","
            "\"sequence\":%lu,\"phase\":\"%s\",\"tick\":%lu,"
            "\"manager_render\":%lu,\"parent_room_call_id\":%lu,"
            "\"parent_world_call_id\":%lu,\"call_id\":%lu,"
            "\"depth\":%lu,\"node_vtable\":\"%s\","
            "\"parent_vtable\":\"%s\",\"geometry_vtable\":\"%s\","
            "\"geometry_polygon_count\":%lu,"
            "\"geometry_extent_f32\":\"0x%08lx\","
            "\"rotation_mode_u32\":%lu,\"cache_u32\":[%lu,%lu],"
            "\"return_u8\":%lu,\"local_rotation_f32\":[",
            (unsigned long)sequence, phase,
            (unsigned long)replay_active_tick,
            (unsigned long)InterlockedCompareExchange(
                &manager_render_count, 0, 0),
            (unsigned long)parent_room_call_id,
            (unsigned long)parent_world_call_id, (unsigned long)call_id,
            (unsigned long)depth, node_identity, parent_identity,
            geometry_identity,
            (unsigned long)(geometry_address ?
                read_u32(geometry, 0x120u) : 0u),
            (unsigned long)(geometry_address ?
                read_u32(geometry, 0x11cu) : 0u),
            (unsigned long)read_u32(node, 0x90u),
            (unsigned long)read_u32(node, 0x18u),
            (unsigned long)read_u32(node, 0x1cu),
            (unsigned long)return_u8)) return;
    for (index = 0u; index < 11u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)read_u32(node, 0xa0u + index * 4u))) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"rotation_aux_f32\":[")) return;
    for (index = 0u; index < 9u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)read_u32(node, 0xccu + index * 4u))) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"world_transform_f32\":[")) return;
    for (index = 0u; index < 14u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)read_u32(node, 0x58u + index * 4u))) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"thread_id\":%lu}\r\n",
            (unsigned long)GetCurrentThreadId())) return;
    append_record(line, (DWORD)size);
}

static void __attribute__((used)) shadow_world_relation_before(
    DWORD node_address)
{
    DWORD call_id, parent_call_id, depth, last_error = GetLastError();
    if (presentation_context_enabled() &&
        active_shadow_render_room_call != INVALID_ID) {
        if (shadow_world_relation_depth >= SHADOW_WORLD_RELATION_DEPTH) {
            session_fail("shadow_world_relation_depth_contract");
        } else {
            depth = shadow_world_relation_depth;
            call_id = next_id(&shadow_world_relation_call_number);
            parent_call_id = depth == 0u ? INVALID_ID :
                shadow_world_relation_calls[depth - 1u];
            shadow_world_relation_calls[depth] = call_id;
            shadow_world_relation_nodes[depth] = node_address;
            shadow_world_relation_rooms[depth] = active_shadow_render_room_call;
            shadow_world_relation_depth = depth + 1u;
            emit_shadow_world_relation_snapshot(
                "BEFORE", node_address, 255u, call_id, parent_call_id, depth,
                active_shadow_render_room_call);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) shadow_world_relation_after(
    DWORD node_address, DWORD return_value)
{
    DWORD depth, call_id, parent_call_id, room_call_id;
    DWORD last_error = GetLastError();
    if (shadow_world_relation_depth != 0u) {
        depth = shadow_world_relation_depth - 1u;
        shadow_world_relation_depth = depth;
        call_id = shadow_world_relation_calls[depth];
        room_call_id = shadow_world_relation_rooms[depth];
        parent_call_id = depth == 0u ? INVALID_ID :
            shadow_world_relation_calls[depth - 1u];
        if (node_address != shadow_world_relation_nodes[depth] ||
            active_shadow_render_room_call != room_call_id) {
            session_fail("shadow_world_relation_stack_contract");
        } else {
            emit_shadow_world_relation_snapshot(
                "AFTER", node_address, return_value & 0xffu, call_id,
                parent_call_id, depth, room_call_id);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((naked)) shadow_world_relation_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tmovl %ecx, %esi\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "pushl %esi\n\tcall _shadow_world_relation_before\n\taddl $4, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "movl %esi, %ecx\n\tcall *_shadow_world_relation_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "pushl 28(%ebx)\n\tpushl %esi\n\t"
        "call _shadow_world_relation_after\n\taddl $8, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %esi\n\tret\n\t");
}

static BOOL shadow_rotation_setter_owner(
    DWORD matrix_address, char *owner_identity, size_t owner_capacity,
    char *parent_identity, size_t parent_capacity,
    char *object_identity, size_t object_capacity,
    char *geometry_identity, size_t geometry_capacity,
    DWORD *object_ordinal, DWORD *geometry_polygon_count,
    DWORD *geometry_extent_f32)
{
    DWORD owner_address, parent_address, child_address, ordinal;
    BYTE owner[0x180u], related[0x180u], geometry[0x124u];
    char child_identity[96];
    if (matrix_address < 0xa0u) return FALSE;
    owner_address = matrix_address - 0xa0u;
    if (copy_readable((const void *)(ULONG_PTR)owner_address,
                      owner, sizeof(owner)) != sizeof(owner) ||
        !stable_module_identity(read_u32(owner, 0u), owner_identity,
                                owner_capacity) ||
        strcmp(owner_identity, "cc.dll+0x00053580") != 0) return FALSE;
    memcpy(parent_identity, "none", 5u);
    memcpy(object_identity, "none", 5u);
    memcpy(geometry_identity, "none", 5u);
    *object_ordinal = INVALID_ID;
    *geometry_polygon_count = 0u;
    *geometry_extent_f32 = 0u;
    parent_address = read_u32(owner, 0x04u);
    if (parent_address != 0u &&
        (copy_readable((const void *)(ULONG_PTR)parent_address,
                       related, sizeof(DWORD)) != sizeof(DWORD) ||
         !stable_module_identity(read_u32(related, 0u), parent_identity,
                                 parent_capacity))) return FALSE;
    child_address = read_u32(owner, 0x08u);
    for (ordinal = 0u; child_address != 0u && ordinal < 64u; ++ordinal) {
        DWORD geometry_address;
        if (copy_readable((const void *)(ULONG_PTR)child_address,
                          related, sizeof(related)) != sizeof(related) ||
            !stable_module_identity(read_u32(related, 0u), child_identity,
                                    sizeof(child_identity))) return FALSE;
        if (strcmp(child_identity, "cc.dll+0x000535e4") == 0) {
            geometry_address = read_u32(related, 0x120u);
            if (strlen(child_identity) + 1u > object_capacity ||
                geometry_address == 0u ||
                copy_readable((const void *)(ULONG_PTR)geometry_address,
                              geometry, sizeof(geometry)) != sizeof(geometry) ||
                !stable_module_identity(read_u32(geometry, 0u),
                                        geometry_identity,
                                        geometry_capacity)) return FALSE;
            memcpy(object_identity, child_identity,
                   strlen(child_identity) + 1u);
            *object_ordinal = ordinal;
            *geometry_polygon_count = read_u32(geometry, 0x120u);
            *geometry_extent_f32 = read_u32(geometry, 0x11cu);
            return TRUE;
        }
        child_address = read_u32(related, 0x0cu);
    }
    return child_address == 0u;
}

static void emit_shadow_rotation_setter_snapshot(
    const char *phase, DWORD matrix_address, DWORD angle_f32,
    DWORD caller_address, DWORD call_id)
{
    DWORD index, sequence, object_ordinal, polygon_count, extent_f32;
    BYTE matrix[11u * sizeof(DWORD)];
    char line[TRACE_LINE_SIZE], owner_identity[96], parent_identity[96];
    char caller_identity[96], object_identity[96], geometry_identity[96];
    int size = 0;
    if (!stable_module_identity(caller_address, caller_identity,
                                sizeof(caller_identity)) ||
        copy_readable((const void *)(ULONG_PTR)matrix_address,
                      matrix, sizeof(matrix)) != sizeof(matrix) ||
        !shadow_rotation_setter_owner(
            matrix_address, owner_identity, sizeof(owner_identity),
            parent_identity, sizeof(parent_identity),
            object_identity, sizeof(object_identity),
            geometry_identity, sizeof(geometry_identity),
            &object_ordinal, &polygon_count, &extent_f32)) {
        session_fail("shadow_rotation_setter_identity_contract");
        return;
    }
    sequence = next_id(&shadow_rotation_setter_sequence_number);
    if (!particle_line_append(
            line, sizeof(line), &size,
            "MVD {\"schema\":1,"
            "\"protocol\":\"miel-vliegt-native-shadow-rotation-setter\","
            "\"sequence\":%lu,\"phase\":\"%s\",\"tick\":%lu,"
            "\"manager_render\":%lu,\"call_id\":%lu,"
            "\"caller\":\"%s\",\"angle_f32\":\"0x%08lx\","
            "\"owner_vtable\":\"%s\",\"parent_vtable\":\"%s\","
            "\"object_ordinal\":%lu,\"object_vtable\":\"%s\","
            "\"geometry_vtable\":\"%s\","
            "\"geometry_polygon_count\":%lu,"
            "\"geometry_extent_f32\":\"0x%08lx\","
            "\"local_rotation_f32\":[",
            (unsigned long)sequence, phase,
            (unsigned long)replay_active_tick,
            (unsigned long)InterlockedCompareExchange(
                &manager_render_count, 0, 0),
            (unsigned long)call_id, caller_identity,
            (unsigned long)angle_f32, owner_identity, parent_identity,
            (unsigned long)object_ordinal, object_identity,
            geometry_identity, (unsigned long)polygon_count,
            (unsigned long)extent_f32)) return;
    for (index = 0u; index < 11u; ++index) {
        if (!particle_line_append(
                line, sizeof(line), &size, "%s\"0x%08lx\"",
                index == 0u ? "" : ",",
                (unsigned long)read_u32(matrix, index * 4u))) return;
    }
    if (!particle_line_append(
            line, sizeof(line), &size, "],\"thread_id\":%lu}\r\n",
            (unsigned long)GetCurrentThreadId())) return;
    append_record(line, (DWORD)size);
}

static void __attribute__((used)) shadow_rotation_setter_before(
    DWORD matrix_address, DWORD angle_f32, DWORD caller_address)
{
    DWORD last_error = GetLastError();
    char owner_identity[96], parent_identity[96], object_identity[96];
    char geometry_identity[96];
    DWORD object_ordinal, polygon_count, extent_f32;
    if (shadow_rotation_setter_owner(
            matrix_address, owner_identity, sizeof(owner_identity),
            parent_identity, sizeof(parent_identity),
            object_identity, sizeof(object_identity),
            geometry_identity, sizeof(geometry_identity),
            &object_ordinal, &polygon_count, &extent_f32) &&
        polygon_count == 80u && extent_f32 == 0x3fa74310u) {
        if (active_shadow_rotation_setter_call != INVALID_ID) {
            session_fail("shadow_rotation_setter_nesting_contract");
        } else {
            active_shadow_rotation_setter_call = next_id(
                &shadow_rotation_setter_call_number);
            active_shadow_rotation_setter_matrix = matrix_address;
            active_shadow_rotation_setter_caller = caller_address;
            emit_shadow_rotation_setter_snapshot(
                "BEFORE", matrix_address, angle_f32, caller_address,
                active_shadow_rotation_setter_call);
        }
    }
    SetLastError(last_error);
}

static void __attribute__((used)) shadow_rotation_setter_after(
    DWORD matrix_address, DWORD angle_f32, DWORD caller_address)
{
    DWORD last_error = GetLastError();
    if (active_shadow_rotation_setter_call != INVALID_ID) {
        if (matrix_address != active_shadow_rotation_setter_matrix ||
            caller_address != active_shadow_rotation_setter_caller) {
            session_fail("shadow_rotation_setter_pair_contract");
        } else {
            emit_shadow_rotation_setter_snapshot(
                "AFTER", matrix_address, angle_f32, caller_address,
                active_shadow_rotation_setter_call);
        }
        active_shadow_rotation_setter_call = INVALID_ID;
    }
    SetLastError(last_error);
}

static void __attribute__((naked)) shadow_rotation_setter_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\tpushl %ebp\n\t"
        "movl %ecx, %esi\n\tmovl 12(%esp), %ebp\n\t"
        "movl 16(%esp), %edi\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "pushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_rotation_setter_before\n\taddl $12, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "pushl %edi\n\tmovl %esi, %ecx\n\t"
        "call *_shadow_rotation_setter_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "pushl %ebp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _shadow_rotation_setter_after\n\taddl $12, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %ebp\n\tpopl %edi\n\tpopl %esi\n\tret $4\n\t");
}

static void *const BODY_PHASE_HOOKS[BODY_PHASE_COUNT] = {
    (void *)(ULONG_PTR)&body_load_hook,
    (void *)(ULONG_PTR)&body_open_hook,
    (void *)(ULONG_PTR)&body_tick_hook,
    (void *)(ULONG_PTR)&body_render_hook,
    (void *)(ULONG_PTR)&body_close_hook,
    (void *)(ULONG_PTR)&body_unload_hook
};

#define SEMANTIC_HOOK(name, arguments, call_body, original_body, resume) \
static void __attribute__((naked)) name(void) \
{ \
    __asm__ __volatile__( \
        "pushfl\n\t" "pushal\n\t" "movl %esp, %ebx\n\t" "cld\n\t" \
        "subl $528, %esp\n\t" "andl $-16, %esp\n\t" "fxsave (%esp)\n\t" \
        arguments call_body \
        "fxrstor (%esp)\n\t" "movl %ebx, %esp\n\t" \
        "popal\n\t" "popfl\n\t" original_body "jmp *" resume "\n\t"); \
}

static void __attribute__((used)) record_manager_render(DWORD manager_node,
                                                        DWORD device_address)
{
    DWORD last_error = GetLastError();
    DWORD current = 0u;
    if (InterlockedExchange(&manager_render_active, 0) != 1) {
        session_fail("manager_render_active_contract");
    }
    InterlockedIncrement(&manager_render_count);
    if (session_state == SESSION_READY && device_address != 0u &&
        read_pointer(manager_node, 0x84u, &current) && current != 0u) {
        if (!calibration_observation_only) record_camera_commit(current);
        record_render_final(current, device_address);
        complete_session_after_render();
    }
    SetLastError(last_error);
}

static void __attribute__((used)) manager_render_enter(void)
{
    if (InterlockedIncrement(&manager_render_active) != 1) {
        session_fail("manager_render_reentrancy_contract");
    }
}

static DWORD __attribute__((used)) manager_tick_prepare(DWORD manager_node,
                                                        DWORD dt_f32_bits)
{
    DWORD manager_address = manager_node - 0x108u;
    DWORD current_thread = GetCurrentThreadId();
    LONG observed_engine_thread;
    if (calibration_observation_only &&
        InterlockedCompareExchange(
            &calibration_manager_identity_validated, 0, 0) != 1 &&
        !validate_calibration_manager_identity(manager_address)) {
        session_fail("calibration_manager_identity_contract");
        return dt_f32_bits;
    }
    InterlockedIncrement(&manager_tick_count);
    observed_engine_thread = InterlockedCompareExchange(
        &engine_thread_id, (LONG)current_thread, 0);
    if (observed_engine_thread == 0) {
        observed_engine_thread = (LONG)current_thread;
    }
    if (native_dispatch_armed && !native_dispatch_bound) {
        if ((DWORD)observed_engine_thread != current_thread ||
            !mvds_bind_engine_thread(current_thread)) {
            session_fail("native_dispatch_engine_thread_contract");
        } else {
            native_dispatch_bound = TRUE;
        }
    }
    record_mode_lifecycle(manager_address);
    dispatch_body_mode_on_manager_tick(manager_address);
    dispatch_native_capture_driver_on_manager_tick(manager_address);
    if (session_state != SESSION_ARMED && session_state != SESSION_READY) {
        if (session_state == SESSION_DISPATCHED &&
            flight_activation_clock_open && replay_ticks != NULL) {
            return record_flight_activation_clock(dt_f32_bits);
        }
        return dt_f32_bits;
    }
    return record_tick(manager_node, dt_f32_bits);
}

static void __attribute__((naked)) manager_render_vtable_hook(void)
{
    __asm__ __volatile__(
        "pushl %esi\n\tpushl %edi\n\t"
        "movl %ecx, %esi\n\tmovl 12(%esp), %edi\n\t"
        "pushfl\n\tpushal\n\tcall _manager_render_enter\n\tpopal\n\tpopfl\n\t"
        "pushl %edi\n\tcall *_manager_render_original\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $8, %esp\n\tpushl %edi\n\tpushl %esi\n\t"
        "call _record_manager_render\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\t"
        "popal\n\tpopfl\n\tpopl %edi\n\tpopl %esi\n\tret $4\n\t");
}

static void __attribute__((naked)) manager_tick_vtable_hook(void)
{
    __asm__ __volatile__(
        "pushfl\n\t" "pushal\n\t" "movl %esp, %ebx\n\t" "cld\n\t"
        "subl $528, %esp\n\t" "andl $-16, %esp\n\t" "fxsave (%esp)\n\t"
        "subl $8, %esp\n\tpushl 40(%ebx)\n\tpushl 24(%ebx)\n\t"
        "call _manager_tick_prepare\n\taddl $16, %esp\n\t"
        "movl %eax, 40(%ebx)\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\t"
        "popal\n\t" "popfl\n\t"
        "jmp *_manager_tick_original\n\t");
}

/* BARN diagnostics deliberately avoid the manager vtable interposition: that
 * hook is the component under isolation.  Login's own Tick entry is a narrower
 * engine-thread boundary and retains the native body through the trampoline. */
static void __attribute__((naked)) login_tick_hook(void)
{
    __asm__ __volatile__(
        "pushfl\n\t" "pushal\n\t" "movl %esp, %ebx\n\t" "cld\n\t"
        "subl $528, %esp\n\t" "andl $-16, %esp\n\t" "fxsave (%esp)\n\t"
        "subl $12, %esp\n\tpushl 24(%ebx)\n\t"
        "call _record_login_tick\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\t"
        "popal\n\t" "popfl\n\t"
        "jmp *_login_tick_trampoline\n\t");
}
static void __attribute__((naked)) mode_set_hook(void)
{
    __asm__ __volatile__(
        /* Private stack words survive the original ret $4: manager, id. */
        "pushl $-1\n\tpushl %ecx\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "pushl 44(%ebx)\n\tleal 40(%ebx), %eax\n\tpushl %eax\n\t"
        "pushl 48(%ebx)\n\tpushl 36(%ebx)\n\t"
        "call _record_mode_transition_entry\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "pushl 12(%esp)\n\tcall *_mode_set_trampoline\n\t"
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "pushl 28(%ebx)\n\tpushl 40(%ebx)\n\tpushl 48(%ebx)\n\t"
        "pushl 36(%ebx)\n\tcall _record_mode_transition_leave\n\t"
        "addl $16, %esp\n\tfxrstor (%esp)\n\tmovl %ebx, %esp\n\t"
        "popal\n\tpopfl\n\taddl $8, %esp\n\tret $4\n\t");
}

static void __attribute__((naked)) flight_target_hook(void)
{
    __asm__ __volatile__(
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $8, %esp\n\tpushl 36(%ebx)\n\tpushl 40(%ebx)\n\t"
        "call _observe_flight_target\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "jmp *_flight_target_trampoline\n\t");
}

static void __attribute__((naked)) queue_mode_hook(void)
{
    __asm__ __volatile__(
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $4, %esp\n\tpushl 36(%ebx)\n\tpushl 40(%ebx)\n\t"
        "pushl 24(%ebx)\n\tcall _observe_queue_mode\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "jmp *_queue_mode_trampoline\n\t");
}

static void __attribute__((naked)) exhibition_callback_hook(void)
{
    __asm__ __volatile__(
        "pushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $8, %esp\n\tpushl 36(%ebx)\n\tpushl 40(%ebx)\n\t"
        "call _natural_exhibition_enter\n\taddl $16, %esp\n\t"
        "movl %eax, 36(%ebx)\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "jmp *_exhibition_callback_trampoline\n\t");
}

static void __attribute__((naked)) exhibition_callback_leave_hook(void)
{
    __asm__ __volatile__(
        /* Keep both the original EAX and the eventual return address on the
         * private stack so the synthetic return preserves every register. */
        "pushl $0\n\tpushl %eax\n\tpushfl\n\tpushal\n\tmovl %esp, %ebx\n\tcld\n\t"
        "subl $528, %esp\n\tandl $-16, %esp\n\tfxsave (%esp)\n\t"
        "subl $12, %esp\n\tcall _natural_exhibition_leave\n\taddl $12, %esp\n\t"
        "movl %eax, 40(%ebx)\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\tpopal\n\tpopfl\n\t"
        "popl %eax\n\tret\n\t");
}
SEMANTIC_HOOK(controls_pre_hook,
              "subl $8, %esp\n\tpushl 48(%ebx)\n\tpushl 4(%ebx)\n\t",
              "call _record_controls_pre\n\taddl $16, %esp\n\t",
              "movl 76(%esi), %ecx\n\ttestl %ecx, %ecx\n\t",
              "_controls_pre_resume")
SEMANTIC_HOOK(controls_post_hook,
              "subl $12, %esp\n\tpushl 4(%ebx)\n\t",
              "call _record_controls_post\n\taddl $16, %esp\n\t",
              "movl 132(%esi), %ecx\n\t", "_controls_post_resume")
SEMANTIC_HOOK(flight_entry_hook,
              "subl $8, %esp\n\tpushl 40(%ebx)\n\tpushl 24(%ebx)\n\t",
              "call _record_physics_entry\n\taddl $16, %esp\n\t",
              "subl $96, %esp\n\tpushl %esi\n\tmovl %ecx, %esi\n\t",
              "_flight_entry_resume")
SEMANTIC_HOOK(flight_leave_hook,
              "subl $12, %esp\n\tpushl 4(%ebx)\n\t",
              "call _record_physics_leave\n\taddl $16, %esp\n\t",
              "movl 0x0045eee4, %ecx\n\t", "_flight_leave_resume")
static void __attribute__((naked)) collision_entry_hook(void)
{
    __asm__ __volatile__(
        "pushfl\n\t" "pushal\n\t" "movl %esp, %ebx\n\t" "cld\n\t"
        "subl $528, %esp\n\t" "andl $-16, %esp\n\t" "fxsave (%esp)\n\t"
        "subl $8, %esp\n\tmovl 12(%ebx), %eax\n\t"
        "pushl 428(%eax)\n\tpushl 8(%ebx)\n\t"
        "call _record_collision_entry\n\taddl $16, %esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx, %esp\n\t"
        "popal\n\t" "popfl\n\t"
        "flds 424(%esp)\n\tjmp *_collision_entry_resume\n\t");
}
SEMANTIC_HOOK(collision_commit_hook,
              "subl $12, %esp\n\tpushl 8(%ebx)\n\t",
              "call _record_collision_commit\n\taddl $16, %esp\n\t",
              "movl 192(%esp), %ecx\n\t", "_collision_commit_resume")
SEMANTIC_HOOK(camera_commit_hook,
              "subl $12, %esp\n\tpushl 8(%ebx)\n\t",
              "call _note_camera_source_commit\n\taddl $16, %esp\n\t",
              "movl 184(%ebp), %ecx\n\t", "_camera_commit_resume")
SEMANTIC_HOOK(render_final_hook,
              "subl $8, %esp\n\tpushl 0(%ebx)\n\tpushl 4(%ebx)\n\t",
              "call _record_render_final\n\taddl $16, %esp\n\t",
              "movl 0x0045f308, %ecx\n\t", "_render_final_resume")
SEMANTIC_HOOK(fuel_depletion_hook,
              "subl $8, %esp\n\tpushl $1\n\tpushl 4(%ebx)\n\t",
              "call _record_fuel\n\taddl $16, %esp\n\t",
              "movl $0x00405a20, %eax\n\tcall *%eax\n\t",
              "_fuel_depletion_resume")
SEMANTIC_HOOK(fuel_post_consume_hook,
              "subl $8, %esp\n\tpushl $0\n\tpushl 4(%ebx)\n\t",
              "call _record_fuel\n\taddl $16, %esp\n\t",
              "movb 315(%esi), %al\n\t", "_fuel_post_consume_resume")
SEMANTIC_HOOK(contact_hook,
              "subl $12, %esp\n\tpushl 8(%ebx)\n\t",
              "call _record_contact\n\taddl $16, %esp\n\t",
              "leal 116(%esp), %ecx\n\tcall *0x0044c1e4\n\t",
              "_contact_resume")
SEMANTIC_HOOK(damage_effective_hook,
              "subl $8, %esp\n\tpushl 48(%ebx)\n\tpushl 4(%ebx)\n\t",
              "call _record_damage_effective\n\taddl $16, %esp\n\t",
              "flds 416(%esi)\n\t", "_damage_effective_resume")
SEMANTIC_HOOK(damage_post_hook,
              "subl $8, %esp\n\tpushl 48(%ebx)\n\tpushl 4(%ebx)\n\t",
              "call _record_damage_post\n\taddl $16, %esp\n\t",
              "fcomps 0x0044c560\n\t", "_damage_post_resume")
SEMANTIC_HOOK(damage_nonterminal_hook,
              "subl $16, %esp\n\t",
              "call _record_damage_nonterminal\n\taddl $16, %esp\n\t",
              "movl 12(%esp), %edx\n\tmovl (%ecx), %eax\n\t",
              "_damage_nonterminal_resume")
SEMANTIC_HOOK(terminal_crash_hook,
              "subl $16, %esp\n\t",
              "call _record_terminal_crash\n\taddl $16, %esp\n\t",
              "pushl %ebx\n\tpushl %esi\n\tmovl %ecx, %esi\n\t"
              "xorl %ebx, %ebx\n\t", "_terminal_crash_resume")
SEMANTIC_HOOK(terrain_result_crash_hook,
              "subl $12, %esp\n\tpushl 28(%ebx)\n\t",
              "call _record_terrain_result\n\taddl $16, %esp\n\t",
              "movl %eax, %ecx\n\tcmpl $7, %ecx\n\t",
              "_terrain_result_crash_resume")
SEMANTIC_HOOK(terrain_result_render_hook,
              "subl $12, %esp\n\tpushl 28(%ebx)\n\t",
              "call _record_terrain_result\n\taddl $16, %esp\n\t",
              "movl 18476(%esi,%eax,4), %ecx\n\t",
              "_terrain_result_render_resume")

static DWORD observation_omit_bit(const BYTE *target)
{
    if (target == PARTICLE_EMITTER_TICK) return OBSERVE_OMIT_PARTICLE_EMITTER;
    if (target == PARTICLE_RESET) return OBSERVE_OMIT_PARTICLE_RESET;
    if (target == PARTICLE_PLACE) return OBSERVE_OMIT_PARTICLE_PLACE;
    if (target == RENDER_LIST_DISPATCH) return OBSERVE_OMIT_RENDER_LIST;
    if (target == AIRPLANE_PRESENTATION) {
        return OBSERVE_OMIT_AIRPLANE_PRESENTATION;
    }
    if (target == shadow_camera_render_target) return OBSERVE_OMIT_SHADOW_CAMERA;
    if (target == shadow_render_room_target) return OBSERVE_OMIT_SHADOW_ROOM;
    if (target == shadow_visible_objects_target) return OBSERVE_OMIT_SHADOW_OBJECTS;
    if (target == shadow_visible_polygons_target) return OBSERVE_OMIT_SHADOW_POLYGONS;
    if (target == shadow_polygon_render_target) {
        return OBSERVE_OMIT_SHADOW_POLYGON_RENDER;
    }
    if (target == shadow_world_relation_target) {
        return OBSERVE_OMIT_SHADOW_WORLD_RELATION;
    }
    if (target == shadow_rotation_setter_target) {
        return OBSERVE_OMIT_SHADOW_ROTATION;
    }
    return 0u;
}

static BOOL calibration_detour_required(const BYTE *target)
{
    return target == MODE_SET ||
        target == CONTROLS_PRE || target == CONTROLS_POST;
}

static BOOL native_dispatch_target_scoped(void)
{
    return native_dispatch_requested &&
        native_dispatch_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2;
}

static BOOL native_dispatch_observer_detour_required(const BYTE *target)
{
    if (scenario_bounded_observation &&
        (target == AUDIO_START || target == AUDIO_POLL)) {
        return TRUE;
    }
    if (!native_dispatch_target_scoped()) return TRUE;
    if (target == MODE_SET) return TRUE;
    if (native_dispatch_capture_target.evidence_class ==
            MVDS_EVIDENCE_MISSION_DISPATCH) {
        return target == SCENE_DISPATCH_GROUND ||
            target == SCENE_DISPATCH_BARN ||
            target == SCENE_DISPATCH_FLIGHT;
    }
    return FALSE;
}

static const MvdsHookSpec *native_dispatch_semantic_spec(const BYTE *target)
{
    size_t index;
    if (!native_dispatch_requested || !native_dispatch_specs) return NULL;
    for (index = 0u; index < native_dispatch_spec_count; ++index) {
        if (native_dispatch_specs[index].target == target) {
            return &native_dispatch_specs[index];
        }
    }
    return NULL;
}

static BOOL native_dispatch_semantic_detour(const BYTE *target)
{
    return native_dispatch_semantic_spec(target) != NULL;
}

static BOOL rel32_relocation_declared(
    const MvdsHookSpec *spec, SIZE_T opcode_offset, BYTE opcode
)
{
    size_t index;
    for (index = 0u; index < spec->rel32_relocation_count; ++index) {
        const MvdsRel32Relocation *relocation =
            &spec->rel32_relocations[index];
        if (relocation->opcode_offset == opcode_offset &&
            (BYTE)relocation->opcode == opcode) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL semantic_rel32_metadata_valid(const MvdsHookSpec *spec)
{
    size_t index, other;
    SIZE_T offset;
    if (!spec ||
        ((spec->rel32_relocations == NULL) !=
         (spec->rel32_relocation_count == 0u))) {
        return FALSE;
    }
    for (index = 0u; index < spec->rel32_relocation_count; ++index) {
        const MvdsRel32Relocation *relocation =
            &spec->rel32_relocations[index];
        BYTE opcode = (BYTE)relocation->opcode;
        if ((opcode != (BYTE)MVDS_REL32_CALL &&
             opcode != (BYTE)MVDS_REL32_JUMP) ||
            relocation->opcode_offset > spec->minimum_patch_size ||
            spec->minimum_patch_size - relocation->opcode_offset < 5u ||
            spec->signature[relocation->opcode_offset] != opcode) {
            return FALSE;
        }
        for (other = 0u; other < index; ++other) {
            size_t other_offset =
                spec->rel32_relocations[other].opcode_offset;
            if ((relocation->opcode_offset >= other_offset &&
                 relocation->opcode_offset - other_offset < 5u) ||
                (other_offset > relocation->opcode_offset &&
                 other_offset - relocation->opcode_offset < 5u)) {
                return FALSE;
            }
        }
    }
    /* The pinned signature is also the instruction-shape contract.  A newly
     * introduced relative CALL/JMP inside the stolen range must not silently
     * pass without corresponding relocation metadata. */
    for (offset = 0u; offset + 5u <= spec->minimum_patch_size; ++offset) {
        BYTE opcode = spec->signature[offset];
        if ((opcode == (BYTE)MVDS_REL32_CALL ||
             opcode == (BYTE)MVDS_REL32_JUMP) &&
            !rel32_relocation_declared(spec, offset, opcode)) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL relocate_rel32_site(
    BYTE *trampoline, const BYTE *target, SIZE_T stolen,
    const MvdsRel32Relocation *relocation
)
{
    LONG original_displacement, relocated_displacement;
    LONGLONG destination, displacement;
    SIZE_T offset = relocation->opcode_offset;
    BYTE opcode = (BYTE)relocation->opcode;
    if ((opcode != (BYTE)MVDS_REL32_CALL &&
         opcode != (BYTE)MVDS_REL32_JUMP) ||
        offset > stolen || stolen - offset < 5u || target[offset] != opcode) {
        return FALSE;
    }
    memcpy(&original_displacement, target + offset + 1u,
           sizeof(original_displacement));
    destination = (LONGLONG)(ULONG_PTR)(target + offset + 5u) +
        (LONGLONG)original_displacement;
    displacement = destination -
        (LONGLONG)(ULONG_PTR)(trampoline + offset + 5u);
    if (displacement < (LONGLONG)INT_MIN ||
        displacement > (LONGLONG)INT_MAX) {
        return FALSE;
    }
    relocated_displacement = (LONG)displacement;
    memcpy(trampoline + offset + 1u, &relocated_displacement,
           sizeof(relocated_displacement));
    return TRUE;
}

static DetourProtectionRecord *detour_protection_find(
    BYTE *target, void **trampoline_slot
)
{
    DWORD index;
    for (index = 0u; index < DETOUR_PROTECTION_CAPACITY; ++index) {
        DetourProtectionRecord *record = &detour_protection_records[index];
        if (record->in_use && record->target == target &&
            record->trampoline_slot == trampoline_slot) {
            return record;
        }
    }
    return NULL;
}

static DetourProtectionRecord *detour_protection_reserve(
    BYTE *target, void **trampoline_slot
)
{
    DWORD index;
    if (!target || !trampoline_slot ||
        detour_protection_find(target, trampoline_slot)) {
        return NULL;
    }
    for (index = 0u; index < DETOUR_PROTECTION_CAPACITY; ++index) {
        DetourProtectionRecord *record = &detour_protection_records[index];
        if (!record->in_use) {
            memset(record, 0, sizeof(*record));
            record->target = target;
            record->trampoline_slot = trampoline_slot;
            record->in_use = TRUE;
            return record;
        }
    }
    return NULL;
}

static void detour_protection_release(DetourProtectionRecord *record)
{
    if (record) memset(record, 0, sizeof(*record));
}

static BOOL restore_detour_target(
    BYTE *target, const BYTE *original, SIZE_T stolen, DWORD final_protect
)
{
    DWORD writable_protect, ignored;
    BOOL cache_flushed, protection_restored;
    if (!VirtualProtect(
            target, stolen, PAGE_EXECUTE_READWRITE, &writable_protect)) {
        return FALSE;
    }
    memcpy(target, original, stolen);
    cache_flushed = FlushInstructionCache(
        GetCurrentProcess(), target, stolen);
    protection_restored = VirtualProtect(
        target, stolen, final_protect, &ignored);
    return cache_flushed && protection_restored;
}

static BOOL install_detour(BYTE *target, const BYTE *signature, SIZE_T stolen,
                           const void *hook, void **trampoline_out)
{
    BYTE *trampoline;
    BYTE patch[16];
    const MvdsHookSpec *semantic_spec;
    DetourProtectionRecord *record;
    size_t relocation_index;
    DWORD old_protect, ignored;
    BOOL cache_flushed, protection_restored;
    INT_PTR displacement;

    if (!trampoline_out || *trampoline_out) return FALSE;
    if (target == diagnostic_skip_target ||
        (diagnostic_session_only && target != LOGIN_TICK &&
         target != MODE_LIFECYCLE_RETURN && target != MODE_SET) ||
        (calibration_observation_only &&
         !calibration_detour_required(target)) ||
        (semantic_observation_only &&
         (semantic_observation_omit_mask & observation_omit_bit(target)) != 0u) ||
        (!native_dispatch_semantic_detour(target) &&
         !native_dispatch_observer_detour_required(target))) {
        *trampoline_out = NULL;
        return TRUE;
    }
    semantic_spec = native_dispatch_semantic_spec(target);
    if (stolen < 5u || stolen > sizeof(patch) ||
        memcmp(target, signature, stolen)) return FALSE;
    if (semantic_spec &&
        (semantic_spec->signature != signature ||
         semantic_spec->minimum_patch_size != stolen ||
         !semantic_rel32_metadata_valid(semantic_spec))) {
        return FALSE;
    }
    trampoline = VirtualAlloc(NULL, stolen + 5u, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!trampoline) return FALSE;
    memcpy(trampoline, target, stolen);
    if (semantic_spec) {
        for (relocation_index = 0u;
             relocation_index < semantic_spec->rel32_relocation_count;
             ++relocation_index) {
            if (!relocate_rel32_site(
                    trampoline, target, stolen,
                    &semantic_spec->rel32_relocations[relocation_index])) {
                VirtualFree(trampoline, 0, MEM_RELEASE);
                return FALSE;
            }
        }
    } else if ((trampoline[0] == 0xe8u || trampoline[0] == 0xe9u) &&
               stolen >= 5u) {
        MvdsRel32Relocation entry_relocation = {
            0u, trampoline[0] == 0xe8u ?
                MVDS_REL32_CALL : MVDS_REL32_JUMP
        };
        if (!relocate_rel32_site(
                trampoline, target, stolen, &entry_relocation)) {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return FALSE;
        }
    }
    trampoline[stolen] = 0xe9;
    displacement = (target + stolen) - (trampoline + stolen + 5u);
    if (displacement < (INT_PTR)INT_MIN || displacement > (INT_PTR)INT_MAX) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return FALSE;
    }
    *(LONG *)(trampoline + stolen + 1u) = (LONG)displacement;
    /* Publish generated code through an explicit RW -> RX transition.  Apart
     * from keeping the trampoline W^X, this gives emulators a page-permission
     * boundary on which to invalidate translated zero-filled code. */
    if (!VirtualProtect(trampoline, stolen + 5u, PAGE_EXECUTE_READ, &ignored) ||
        !FlushInstructionCache(
            GetCurrentProcess(), trampoline, stolen + 5u)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return FALSE;
    }

    memset(patch, 0x90, stolen);
    patch[0] = 0xe9;
    displacement = (const BYTE *)hook - (target + 5u);
    if (displacement < (INT_PTR)INT_MIN || displacement > (INT_PTR)INT_MAX) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return FALSE;
    }
    record = detour_protection_reserve(target, trampoline_out);
    if (!record) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return FALSE;
    }
    if (!VirtualProtect(
            target, stolen, PAGE_EXECUTE_READWRITE, &old_protect)) {
        detour_protection_release(record);
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return FALSE;
    }
    record->original_protect = old_protect;
    record->original_protect_known = TRUE;
    *(LONG *)(patch + 1u) = (LONG)displacement;
    memcpy(target, patch, stolen);
    /* Publish before either post-patch operation can fail.  From this point a
     * live target JMP must always retain its executable trampoline. */
    *trampoline_out = trampoline;
    cache_flushed = FlushInstructionCache(
        GetCurrentProcess(), target, stolen);
    protection_restored = VirtualProtect(
        target, stolen, record->original_protect, &ignored);
    if (cache_flushed && protection_restored) return TRUE;

    /* Installation is not successful until both post-patch operations pass.
     * Try to restore the original target transactionally.  On any restoration
     * or free failure the published trampoline remains live and non-NULL; the
     * hard-failure rollback path will retry while keeping this DLL pinned. */
    if (restore_detour_target(
            target, signature, stolen, record->original_protect) &&
        VirtualFree(trampoline, 0, MEM_RELEASE)) {
        *trampoline_out = NULL;
        detour_protection_release(record);
    }
    return FALSE;
}

static BOOL diagnostic_skip_target_allowed(BYTE *target)
{
    return target == FLIGHT_TICK || target == LOGIN_TICK ||
        target == MODE_LIFECYCLE_RETURN || target == UDSP_DISPATCH ||
        target == CONTROLS_PRE ||
        target == CONTROLS_POST || target == FLIGHT_STEP_ENTRY ||
        target == FLIGHT_STEP_LEAVE || target == COLLISION_ENTRY ||
        target == COLLISION_COMMIT || target == CAMERA_COMMIT ||
        target == RENDER_FINAL || target == FUEL_DEPLETION ||
        target == FUEL_POST_CONSUME || target == CONTACT_SITE ||
        target == DAMAGE_EFFECTIVE || target == DAMAGE_POST ||
        target == DAMAGE_NONTERMINAL || target == TERMINAL_CRASH ||
        target == TERRAIN_RESULT_CRASH || target == TERRAIN_RESULT_RENDER;
}

static BOOL configure_body_dispatch(void)
{
    DWORD mode_length = GetEnvironmentVariableA(
        "MIEL_OBSERVER_BODY_MODE", body_mode_name, sizeof(body_mode_name));
    DWORD receipt_length = GetEnvironmentVariableA(
        "MIEL_OBSERVER_BODY_RECEIPT", body_receipt_path,
        sizeof(body_receipt_path));
    char diagnostic[2];
    char position_probe[2] = {0};
    DWORD position_probe_length = GetEnvironmentVariableA(
        "MIEL_OBSERVER_BODY_POSITION_PROBE", position_probe,
        sizeof(position_probe));
    if (mode_length == 0u && receipt_length == 0u) return TRUE;
    if (mode_length == 0u || mode_length >= sizeof(body_mode_name) ||
        receipt_length == 0u || receipt_length >= sizeof(body_receipt_path) ||
        !body_mode_allowed(body_mode_name) ||
        strpbrk(body_receipt_path, "\r\n") != NULL ||
        GetEnvironmentVariableA("MIEL_OBSERVER_DIAGNOSTIC_SKIP_TARGET",
                                diagnostic, sizeof(diagnostic)) != 0u ||
        GetEnvironmentVariableA("MIEL_OBSERVER_DIAGNOSTIC_PROFILE",
                                diagnostic, sizeof(diagnostic)) != 0u) {
        return FALSE;
    }
    if (position_probe_length != 0u &&
        (position_probe_length != 1u || position_probe[0] != '1' ||
         strcmp(body_mode_name, "mode_gabriellagourmet") != 0)) {
        return FALSE;
    }
    body_position_probe_enabled = position_probe_length == 1u;
    InterlockedExchange(&body_dispatch_state, BODY_DISPATCH_WAIT_BARN);
    return TRUE;
}

static BOOL observer_environment_value(
    const char *name, char *value, DWORD capacity, DWORD *length, BOOL *present)
{
    DWORD error;
    SetLastError(ERROR_SUCCESS);
    *length = GetEnvironmentVariableA(name, value, capacity);
    error = GetLastError();
    *present = *length != 0u || error != ERROR_ENVVAR_NOT_FOUND;
    return *length < capacity;
}

static BOOL configure_scene_dispatch_observation(void)
{
    char enabled[2] = {0};
    char incompatible[2] = {0};
    DWORD length = 0u;
    BOOL present = FALSE;
    if (!observer_environment_value(
            "MIEL_OBSERVER_SCENE_DISPATCH", enabled, sizeof(enabled),
            &length, &present)) return FALSE;
    if (!present) return TRUE;
    if (length != 1u || enabled[0] != '1' ||
        GetEnvironmentVariableA("MIEL_OBSERVER_DIAGNOSTIC_SKIP_TARGET",
                                incompatible, sizeof(incompatible)) != 0u ||
        GetEnvironmentVariableA("MIEL_OBSERVER_DIAGNOSTIC_PROFILE",
                                incompatible, sizeof(incompatible)) != 0u) {
        return FALSE;
    }
    scene_dispatch_observation_enabled = TRUE;
    return TRUE;
}

static BOOL native_dispatch_sha256_text(const char *value)
{
    BYTE digest[32];
    return value && decode_sha256(value, digest);
}

static BOOL native_dispatch_identity_text(const char *value, size_t capacity)
{
    const unsigned char *cursor = (const unsigned char *)value;
    size_t length = 0u;
    if (!value || !*value) return FALSE;
    while (*cursor) {
        if (++length >= capacity ||
            !((*cursor >= 'a' && *cursor <= 'z') ||
              (*cursor >= 'A' && *cursor <= 'Z') ||
              (*cursor >= '0' && *cursor <= '9') ||
              strchr("._:/#-", *cursor) != NULL)) {
            return FALSE;
        }
        ++cursor;
    }
    return TRUE;
}

static const MvdsCaptureTarget *native_dispatch_capture_target_lookup(void)
{
    const MvdsCaptureTarget *matched = NULL;
    DWORD index, count = 0u;
    if (MVDS_CAPTURE_TARGET_COUNT !=
        (DWORD)(sizeof(MVDS_CAPTURE_TARGETS) /
                sizeof(MVDS_CAPTURE_TARGETS[0]))) {
        return NULL;
    }
    for (index = 0u; index < MVDS_CAPTURE_TARGET_COUNT; ++index) {
        const MvdsCaptureTarget *target = &MVDS_CAPTURE_TARGETS[index];
        if (!strcmp(target->target_sha256, native_dispatch_target_sha256) &&
            !strcmp(target->job_id, native_dispatch_job_id) &&
            !strcmp(target->job_sha256, native_dispatch_job_sha256) &&
            !strcmp(target->claim_id, native_dispatch_claim_id) &&
            !strcmp(target->claim_sha256, native_dispatch_claim_sha256) &&
            !strcmp(target->subject_sha256, native_dispatch_subject_sha256) &&
            !strcmp(target->expectation_sha256,
                    native_dispatch_expectation_sha256) &&
            !strcmp(target->scenario_sha256,
                    native_dispatch_scenario_sha256) &&
            !strcmp(target->capture_plan_sha256,
                    native_dispatch_capture_plan_sha256) &&
            !strcmp(target->plan_manifest_sha256,
                    native_dispatch_plan_manifest_sha256) &&
            !strcmp(target->native_slice_sha256,
                    native_dispatch_native_slice_sha256)) {
            matched = target;
            ++count;
        }
    }
    return count == 1u ? matched : NULL;
}

static BOOL publish_native_dispatch_process_identity(void)
{
    char name[96];
    DWORD process_id = mvds_native_process_id();
    const char *session_id = mvds_capture_session_id();
    int length;
    if (!process_id || process_id != GetCurrentProcessId() || !session_id ||
        !native_dispatch_identity_text(session_id,MVDS_CAPTURE_SESSION_CAP)) {
        return FALSE;
    }
    length = snprintf(name,sizeof(name),MVDS_IDENTITY_MAPPING_PREFIX "%lu",
                      (unsigned long)process_id);
    if (length <= 0 || (size_t)length >= sizeof(name)) return FALSE;
    native_dispatch_identity_mapping = OpenFileMappingA(
        FILE_MAP_READ | FILE_MAP_WRITE,FALSE,name);
    if (!native_dispatch_identity_mapping) return FALSE;
    native_dispatch_shared_identity = (MvdsSharedProcessIdentity *)MapViewOfFile(
        native_dispatch_identity_mapping,FILE_MAP_READ | FILE_MAP_WRITE,0,0,
        sizeof(MvdsSharedProcessIdentity));
    if (!native_dispatch_shared_identity ||
        native_dispatch_shared_identity->schema != 0u ||
        native_dispatch_shared_identity->native_process_id != 0u ||
        InterlockedCompareExchange(
            &native_dispatch_shared_identity->ready,0,0) != 0 ||
        InterlockedCompareExchange(
            &native_dispatch_shared_identity->capture_complete,0,0) != 0) {
        return FALSE;
    }
    native_dispatch_shared_identity->schema = 1u;
    native_dispatch_shared_identity->native_process_id = process_id;
    strcpy(native_dispatch_shared_identity->capture_session_id,session_id);
    MemoryBarrier();
    InterlockedExchange(&native_dispatch_shared_identity->ready,1);
    return TRUE;
}

static BOOL configure_native_dispatch_producer(void)
{
    typedef struct NativeDispatchEnvironmentField {
        const char *name;
        char *value;
        DWORD capacity;
        DWORD length;
        BOOL present;
    } NativeDispatchEnvironmentField;
    char enabled[2] = {0};
    const MvdsCaptureTarget *matched;
    DWORD index;
    DWORD enabled_length = 0u;
    BOOL enabled_present = FALSE;
    NativeDispatchEnvironmentField fields[] = {
        {"MIEL_OBSERVER_NATIVE_DISPATCH_JOB_ID", native_dispatch_job_id,
         sizeof(native_dispatch_job_id), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_SLICE_SHA256",
         native_dispatch_native_slice_sha256,
         sizeof(native_dispatch_native_slice_sha256), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_BINARY_SHA256",
         native_dispatch_observer_binary_sha256,
         sizeof(native_dispatch_observer_binary_sha256), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_BUILD_RECEIPT_SHA256",
         native_dispatch_build_receipt_sha256,
         sizeof(native_dispatch_build_receipt_sha256), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_TARGET_SHA256",
         native_dispatch_target_sha256,
         sizeof(native_dispatch_target_sha256), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_JOB_SHA256",
         native_dispatch_job_sha256,
         sizeof(native_dispatch_job_sha256), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_CLAIM_ID", native_dispatch_claim_id,
         sizeof(native_dispatch_claim_id), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_CLAIM_SHA256",
         native_dispatch_claim_sha256,
         sizeof(native_dispatch_claim_sha256), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_SUBJECT_SHA256",
         native_dispatch_subject_sha256,
         sizeof(native_dispatch_subject_sha256), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_EXPECTATION_SHA256",
         native_dispatch_expectation_sha256,
         sizeof(native_dispatch_expectation_sha256), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_SCENARIO_SHA256",
         native_dispatch_scenario_sha256,
         sizeof(native_dispatch_scenario_sha256), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_CAPTURE_PLAN_SHA256",
         native_dispatch_capture_plan_sha256,
         sizeof(native_dispatch_capture_plan_sha256), 0u, FALSE},
        {"MIEL_OBSERVER_NATIVE_DISPATCH_PLAN_MANIFEST_SHA256",
         native_dispatch_plan_manifest_sha256,
         sizeof(native_dispatch_plan_manifest_sha256), 0u, FALSE},
    };
    BOOL any_field = FALSE;
    if (!observer_environment_value(
            "MIEL_OBSERVER_NATIVE_DISPATCH", enabled, sizeof(enabled),
            &enabled_length, &enabled_present)) return FALSE;
    for (index = 0u; index < sizeof(fields) / sizeof(fields[0]); ++index) {
        if (!observer_environment_value(
                fields[index].name, fields[index].value,
                fields[index].capacity, &fields[index].length,
                &fields[index].present)) return FALSE;
        if (fields[index].present) any_field = TRUE;
    }
    if (!enabled_present && !any_field) return TRUE;
    if (!enabled_present || enabled_length != 1u || enabled[0] != '1' ||
        !scene_dispatch_observation_enabled) {
        return FALSE;
    }
    for (index = 0u; index < sizeof(fields) / sizeof(fields[0]); ++index) {
        if (!fields[index].present || fields[index].length == 0u ||
            fields[index].length >= fields[index].capacity) return FALSE;
    }
    if (!native_dispatch_identity_text(
            native_dispatch_job_id, sizeof(native_dispatch_job_id)) ||
        !native_dispatch_identity_text(
            native_dispatch_claim_id, sizeof(native_dispatch_claim_id)) ||
        !native_dispatch_sha256_text(native_dispatch_native_slice_sha256) ||
        !native_dispatch_sha256_text(native_dispatch_observer_binary_sha256) ||
        !native_dispatch_sha256_text(native_dispatch_build_receipt_sha256) ||
        !native_dispatch_sha256_text(native_dispatch_target_sha256) ||
        !native_dispatch_sha256_text(native_dispatch_job_sha256) ||
        !native_dispatch_sha256_text(native_dispatch_claim_sha256) ||
        !native_dispatch_sha256_text(native_dispatch_subject_sha256) ||
        !native_dispatch_sha256_text(native_dispatch_expectation_sha256) ||
        !native_dispatch_sha256_text(native_dispatch_scenario_sha256) ||
        !native_dispatch_sha256_text(native_dispatch_capture_plan_sha256) ||
        !native_dispatch_sha256_text(native_dispatch_plan_manifest_sha256)) {
        return FALSE;
    }
    matched = native_dispatch_capture_target_lookup();
    if (!matched) return FALSE;
    native_dispatch_capture_target = *matched;
    if (!mvds_configure_capture_target(&native_dispatch_capture_target)) {
        return FALSE;
    }
    if (!publish_native_dispatch_process_identity()) return FALSE;
    memset(&native_dispatch_host, 0, sizeof(native_dispatch_host));
    native_dispatch_host.emit_line = native_dispatch_emit_line;
    native_dispatch_host.fail_closed = native_dispatch_fail;
    native_dispatch_host.capture_completed = native_dispatch_capture_completed;
    native_dispatch_host.capture_plan_job_id = native_dispatch_job_id;
    native_dispatch_host.native_slice_sha256 =
        native_dispatch_native_slice_sha256;
    native_dispatch_host.observer_binary_sha256 =
        native_dispatch_observer_binary_sha256;
    native_dispatch_host.observer_build_receipt_sha256 =
        native_dispatch_build_receipt_sha256;
    native_dispatch_requested = TRUE;
    return TRUE;
}

static BOOL configure_native_capture_driver_bootstrap(void)
{
    char version[64] = {0};
    char profile[64] = {0};
    char profile_hash[65] = {0};
    char scenario_hash[65] = {0};
    char initial_user_hash[65] = {0};
    DWORD version_length = 0u, profile_length = 0u, profile_hash_length = 0u;
    DWORD scenario_hash_length = 0u, initial_user_hash_length = 0u;
    BOOL version_present = FALSE, profile_present = FALSE;
    BOOL profile_hash_present = FALSE, scenario_hash_present = FALSE;
    BOOL initial_user_hash_present = FALSE;
    if (!observer_environment_value(
            "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER", version,
            sizeof(version), &version_length, &version_present) ||
        !observer_environment_value(
            "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER_BOOTSTRAP_PROFILE", profile,
            sizeof(profile), &profile_length, &profile_present) ||
        !observer_environment_value(
            "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER_BOOTSTRAP_PROFILE_SHA256",
            profile_hash, sizeof(profile_hash), &profile_hash_length,
            &profile_hash_present) ||
        !observer_environment_value(
            "MIEL_OBSERVER_SCENARIO_SHA256", scenario_hash,
            sizeof(scenario_hash), &scenario_hash_length,
            &scenario_hash_present) ||
        !observer_environment_value(
            "MIEL_OBSERVER_INITIAL_USER_SHA256", initial_user_hash,
            sizeof(initial_user_hash), &initial_user_hash_length,
            &initial_user_hash_present)) return FALSE;
    if (!version_present && !profile_present && !profile_hash_present) {
        native_capture_driver_bootstrap_requested = FALSE;
        return TRUE;
    }
    /* Any mismatch means the fixed driver foundation differs. */
    if (!version_present || !profile_present || !profile_hash_present ||
        !scenario_hash_present || !initial_user_hash_present ||
        strcmp(version, "GENERIC_LOCATION_CLEAN_V2") != 0 ||
        strcmp(profile, NATIVE_CAPTURE_DRIVER_BOOTSTRAP_PROFILE) != 0 ||
        strcmp(profile_hash,
               NATIVE_CAPTURE_DRIVER_BOOTSTRAP_PROFILE_SHA256) != 0 ||
        strcmp(scenario_hash, NATIVE_CAPTURE_DRIVER_SCENARIO_SHA256) != 0 ||
        strcmp(initial_user_hash,
               NATIVE_CAPTURE_DRIVER_INITIAL_USER_SHA256) != 0 ||
        version_length != strlen("GENERIC_LOCATION_CLEAN_V2") ||
        profile_length != strlen(NATIVE_CAPTURE_DRIVER_BOOTSTRAP_PROFILE) ||
        profile_hash_length != 64u || scenario_hash_length != 64u ||
        initial_user_hash_length != 64u) return FALSE;
    native_capture_driver_bootstrap_requested = TRUE;
    return TRUE;
}

static BOOL configure_native_capture_driver(void)
{
    char version[64] = {0};
    char incompatible[2] = {0};
    char forbidden_mode[2] = {0};
    DWORD version_length = 0u, receipt_length = 0u;
    DWORD forbidden_length = 0u;
    BOOL version_present = FALSE, receipt_present = FALSE;
    BOOL forbidden_present = FALSE;
    if (!observer_environment_value(
            "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER", version,
            sizeof(version), &version_length, &version_present) ||
        !observer_environment_value(
            "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER_RECEIPT",
            native_capture_driver_receipt_path,
            sizeof(native_capture_driver_receipt_path),
            &receipt_length, &receipt_present) ||
        !observer_environment_value(
            "MIEL_OBSERVER_NATIVE_DISPATCH_MODE", forbidden_mode,
            sizeof(forbidden_mode), &forbidden_length, &forbidden_present)) {
        return FALSE;
    }
    if (!version_present && !receipt_present && !forbidden_present) return TRUE;
    if (forbidden_present || !version_present || !receipt_present ||
        version_length == 0u || version_length >= sizeof(version) ||
        receipt_length == 0u ||
        receipt_length >= sizeof(native_capture_driver_receipt_path) ||
        strpbrk(native_capture_driver_receipt_path, "\r\n") != NULL ||
        !native_capture_driver_bootstrap_requested ||
        !native_dispatch_requested ||
        native_dispatch_capture_target.evidence_class !=
            MVDS_EVIDENCE_LOCATION_POLICY ||
        strcmp(native_dispatch_capture_target.driver_bootstrap_profile_sha256,
            NATIVE_CAPTURE_DRIVER_BOOTSTRAP_PROFILE_SHA256) != 0 ||
        strcmp(native_dispatch_capture_target.driver_scenario_sha256,
            NATIVE_CAPTURE_DRIVER_SCENARIO_SHA256) != 0 ||
        strcmp(native_dispatch_capture_target.driver_initial_user_sha256,
            NATIVE_CAPTURE_DRIVER_INITIAL_USER_SHA256) != 0 ||
        body_dispatch_state != BODY_DISPATCH_DISABLED ||
        GetEnvironmentVariableA("MIEL_OBSERVER_DIAGNOSTIC_SKIP_TARGET",
                                incompatible, sizeof(incompatible)) != 0u ||
        GetEnvironmentVariableA("MIEL_OBSERVER_DIAGNOSTIC_PROFILE",
                                incompatible, sizeof(incompatible)) != 0u) {
        return FALSE;
    }
    if (strcmp(version, "GENERIC_LOCATION_CLEAN_V2") == 0) {
        if (native_dispatch_capture_target.capture_driver !=
                MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2 ||
            native_dispatch_capture_target.trigger.location.hook_family !=
                MVDS_CAPTURE_HOOK_GENERIC_LOCATION_ENTER ||
            strcmp(native_dispatch_capture_target.trigger.location.selector,
                "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3") != 0) {
            return FALSE;
        }
    } else if (strcmp(version, "BOOTSTRAP_TRAVERSAL_V1") == 0) {
        if (native_dispatch_capture_target.capture_driver !=
                MVDS_CAPTURE_DRIVER_BOOTSTRAP_TRAVERSAL_V1 ||
            native_dispatch_capture_target.trigger.location.hook_family !=
                MVDS_CAPTURE_HOOK_MYGGHANGET_ENTER ||
            strcmp(native_dispatch_capture_target.trigger.location.selector,
                "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE") != 0) {
            return FALSE;
        }
    } else if (strcmp(version, "MISSION_LOCATION_ENTER_V1") == 0) {
        if (native_dispatch_capture_target.capture_driver !=
                MVDS_CAPTURE_DRIVER_MISSION_LOCATION_ENTER_V1 ||
            native_dispatch_capture_target.evidence_class !=
                MVDS_EVIDENCE_MISSION_DISPATCH ||
            native_dispatch_capture_target.trigger.mission.hook_family !=
                MVDS_CAPTURE_HOOK_ACTION_GROUND ||
            strcmp(native_dispatch_capture_target.trigger.mission.mission_phase,
                "activate") != 0) {
            return FALSE;
        }
    } else if (strcmp(version, "MISSION_BARN_TRAVERSAL_V1") == 0) {
        if (native_dispatch_capture_target.capture_driver !=
                MVDS_CAPTURE_DRIVER_MISSION_BARN_TRAVERSAL_V1 ||
            native_dispatch_capture_target.evidence_class !=
                MVDS_EVIDENCE_MISSION_DISPATCH ||
            native_dispatch_capture_target.trigger.mission.hook_family !=
                MVDS_CAPTURE_HOOK_ACTION_BARN ||
            strcmp(native_dispatch_capture_target.trigger.mission.mission_phase,
                "activate") != 0) {
            return FALSE;
        }
    } else {
        return FALSE;
    }
    memset(&native_capture_driver, 0, sizeof(native_capture_driver));
    InterlockedExchange(
        &native_capture_driver_state,
        NATIVE_CAPTURE_DRIVER_WAIT_FLIGHT_READY);
    return TRUE;
}

static BOOL configure_diagnostic_skip_target(void)
{
    char diagnostics[2] = {0};
    char text[32] = {0};
    char *end = NULL;
    unsigned long address;
    DWORD length = GetEnvironmentVariableA(
        "MIEL_OBSERVER_DIAGNOSTIC_SKIP_TARGET", text, sizeof(text));
    if (length == 0u) return TRUE;
    if (length >= sizeof(text) ||
        GetEnvironmentVariableA("MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS",
                                diagnostics, sizeof(diagnostics)) != 1u ||
        diagnostics[0] != '1') return FALSE;
    address = strtoul(text, &end, 0);
    if (end == text || *end != '\0') return FALSE;
    diagnostic_skip_target = (BYTE *)(ULONG_PTR)(DWORD)address;
    return diagnostic_skip_target_allowed(diagnostic_skip_target);
}

static BOOL configure_diagnostic_profile(void)
{
    char diagnostics[2] = {0};
    char profile[32] = {0};
    DWORD length = GetEnvironmentVariableA(
        "MIEL_OBSERVER_DIAGNOSTIC_PROFILE", profile, sizeof(profile));
    if (length == 0u) return TRUE;
    if (length >= sizeof(profile) ||
        GetEnvironmentVariableA("MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS",
                                diagnostics, sizeof(diagnostics)) != 1u ||
        diagnostics[0] != '1' ||
        (strcmp(profile, "session-only") &&
         strcmp(profile, "barn-session"))) {
        return FALSE;
    }
    diagnostic_session_only = TRUE;
    if (!strcmp(profile, "barn-session")) {
        diagnostic_direct_login_tick = TRUE;
        diagnostic_skip_manager_tick = TRUE;
    }
    return TRUE;
}

static BOOL observation_omit_mask_is_coherent(DWORD mask)
{
    DWORD shadow_omissions =
        mask & OBSERVE_OMIT_AIRPLANE_SHADOW_FAMILY;
    return shadow_omissions == 0u ||
        shadow_omissions == OBSERVE_OMIT_AIRPLANE_SHADOW_FAMILY;
}

static BOOL configure_observation_profile(void)
{
    char profile[32] = {0};
    char omit_mask[32] = {0};
    char incompatible[2] = {0};
    char divergent_opt_in[2] = {0};
    char *end = NULL;
    unsigned long parsed_mask;
    DWORD length = GetEnvironmentVariableA(
        "MIEL_OBSERVER_OBSERVATION_PROFILE", profile, sizeof(profile));
    if (length == 0u) return TRUE;
    if (length >= sizeof(profile) ||
        (strcmp(profile, MVOP_SEMANTIC_OBSERVER_PROFILE) &&
         strcmp(profile, "semantic-only") &&
         strcmp(profile, "calibration-only")) ||
        body_dispatch_state != BODY_DISPATCH_DISABLED ||
        GetEnvironmentVariableA("MIEL_OBSERVER_DIAGNOSTIC_SKIP_TARGET",
                                incompatible, sizeof(incompatible)) != 0u ||
        GetEnvironmentVariableA("MIEL_OBSERVER_DIAGNOSTIC_PROFILE",
                                incompatible, sizeof(incompatible)) != 0u) {
        return FALSE;
    }
    if (!strcmp(profile, "calibration-only")) {
        if (!runtime_state_calibration ||
            scene_dispatch_observation_enabled ||
            native_dispatch_requested ||
            natural_capture_edge != NULL ||
            GetEnvironmentVariableA(
                "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE",
                divergent_opt_in, sizeof(divergent_opt_in)) != 0u ||
            GetEnvironmentVariableA(
                "MIEL_OBSERVER_OBSERVATION_OMIT_MASK",
                omit_mask, sizeof(omit_mask)) != 0u) {
            return FALSE;
        }
        calibration_observation_only = TRUE;
        semantic_observation_only = TRUE;
        semantic_observation_omit_mask = OBSERVE_OMIT_ALL;
        return TRUE;
    }
    if (!strcmp(profile, MVOP_SEMANTIC_OBSERVER_PROFILE)) {
        if (scene_dispatch_observation_enabled ||
            native_dispatch_requested ||
            natural_capture_edge != NULL ||
            GetEnvironmentVariableA(
                "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE",
                divergent_opt_in, sizeof(divergent_opt_in)) != 0u) {
            return FALSE;
        }
        scenario_bounded_observation = TRUE;
    } else {
        if (!scene_dispatch_observation_enabled) return FALSE;
        if (GetEnvironmentVariableA(
                "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE",
                divergent_opt_in, sizeof(divergent_opt_in)) != 1u ||
            divergent_opt_in[0] != '1') {
            return FALSE;
        }
    }
    /* Observation cost changes, native semantics do not.  Manager/replay
     * input, mode/landing, flight semantics, UDSP/root and opcode-9 boundaries
     * remain observed; every omitted target is still signature-preflighted.
     * scenario-bounded uses the native scheduler and may omit the complete
     * coherent visual family.  semantic-only remains a divergent diagnostic. */
    semantic_observation_only = TRUE;
    semantic_observation_omit_mask = scenario_bounded_observation ?
        MVOP_SEMANTIC_OMIT_MASK : OBSERVE_OMIT_SEMANTIC_DEFAULT;
    length = GetEnvironmentVariableA(
        "MIEL_OBSERVER_OBSERVATION_OMIT_MASK", omit_mask, sizeof(omit_mask));
    if (scenario_bounded_observation && length == 0u) return FALSE;
    if (length != 0u) {
        if (length >= sizeof(omit_mask)) return FALSE;
        parsed_mask = strtoul(omit_mask, &end, 0);
        if (end == omit_mask || *end != '\0' || parsed_mask > OBSERVE_OMIT_ALL) {
            return FALSE;
        }
        semantic_observation_omit_mask = (DWORD)parsed_mask;
    }
    if (scenario_bounded_observation &&
        semantic_observation_omit_mask != MVOP_SEMANTIC_OMIT_MASK) {
        return FALSE;
    }
    /* Airplane presentation owns the shadow IAT parent call; that boundary in
     * turn owns every nested shadow detour.  Installing only part of this
     * observation family makes valid native calls look structurally corrupt,
     * so reject the profile before any game or replay state can run. */
    if (!observation_omit_mask_is_coherent(
            semantic_observation_omit_mask)) {
        return FALSE;
    }
    return TRUE;
}

static BOOL configure_natural_transition_capture(void)
{
    DWORD index;
    natural_capture_edge = NULL;
    for (index = 0u; index < NATURAL_TRANSITION_COUNT; ++index) {
        const NaturalTransitionEdge *edge = &NATURAL_TRANSITION_EDGES[index];
        if (strcmp(replay_scenario, edge->id) == 0) {
            if (natural_capture_edge) return FALSE;
            natural_capture_edge = edge;
        }
    }
    if (!natural_capture_edge) return TRUE;
    if (body_dispatch_state != BODY_DISPATCH_DISABLED ||
        bootstrap_diagnostics_enabled || diagnostic_session_only ||
        diagnostic_skip_target) {
        natural_capture_edge = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL rollback_detour(BYTE *target, const BYTE *original, SIZE_T stolen,
                            void **trampoline)
{
    DetourProtectionRecord *record;
    void *installed;
    if (!trampoline) {
        detour_rollback_failed = TRUE;
        return FALSE;
    }
    installed = *trampoline;
    record = detour_protection_find(target, trampoline);
    if (!installed) {
        if (!record) return TRUE;
        detour_rollback_failed = TRUE;
        return FALSE;
    }
    if (!record || !record->original_protect_known ||
        !restore_detour_target(
            target, original, stolen, record->original_protect)) {
        detour_rollback_failed = TRUE;
        return FALSE;
    }
    if (!VirtualFree(installed, 0, MEM_RELEASE)) {
        detour_rollback_failed = TRUE;
        return FALSE;
    }
    *trampoline = NULL;
    detour_protection_release(record);
    return TRUE;
}

static void rollback_detour_accumulating(
    BOOL *all_restored, BYTE *target, const BYTE *original, SIZE_T stolen,
    void **trampoline
)
{
    if (!rollback_detour(target, original, stolen, trampoline)) {
        *all_restored = FALSE;
    }
}

static BOOL native_dispatch_signatures_match(void)
{
    size_t index;
    if (!native_dispatch_requested) return TRUE;
    native_dispatch_specs = mvds_hook_specs(&native_dispatch_spec_count);
    if (!native_dispatch_specs ||
        native_dispatch_spec_count != (size_t)MVDS_HOOK_COUNT) {
        return FALSE;
    }
    for (index = 0u; index < native_dispatch_spec_count; ++index) {
        const MvdsHookSpec *spec = &native_dispatch_specs[index];
        if (spec->id != (MvdsHookId)index || !spec->name || !spec->target ||
            !spec->signature || spec->signature_size < spec->minimum_patch_size ||
            spec->minimum_patch_size < 5u || spec->minimum_patch_size > 16u ||
            !spec->hook || !spec->trampoline_slot || *spec->trampoline_slot ||
            !semantic_rel32_metadata_valid(spec) ||
            memcmp(spec->target, spec->signature, spec->signature_size) != 0) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL install_native_dispatch_detours(void)
{
    size_t index;
    if (!native_dispatch_requested) return TRUE;
    if (!native_dispatch_specs || native_dispatch_installed_count != 0u) {
        return FALSE;
    }
    for (index = 0u; index < native_dispatch_spec_count; ++index) {
        const MvdsHookSpec *spec = &native_dispatch_specs[index];
        DWORD bit = 1u << (DWORD)spec->id;
        if (!mvds_hook_required(spec->id)) continue;
        if (!install_detour(
                spec->target, spec->signature, spec->minimum_patch_size,
                spec->hook, spec->trampoline_slot)) {
            /* A post-patch protection/flush failure deliberately leaves its
             * live trampoline published.  Include that partial installation
             * in the reverse rollback transaction. */
            if (*spec->trampoline_slot) {
                native_dispatch_installed_mask |= bit;
                ++native_dispatch_installed_count;
            }
            return FALSE;
        }
        native_dispatch_installed_mask |= bit;
        ++native_dispatch_installed_count;
    }
    if (!mvds_arm(
            &native_dispatch_host,
            !native_dispatch_target_scoped())) return FALSE;
    native_dispatch_armed = TRUE;
    return TRUE;
}

static BOOL rollback_native_dispatch_detours(void)
{
    size_t index;
    if (!native_dispatch_requested) return TRUE;
    mvds_disable();
    native_dispatch_armed = FALSE;
    native_dispatch_bound = FALSE;
    for (index = native_dispatch_spec_count; index != 0u; --index) {
        const MvdsHookSpec *spec = &native_dispatch_specs[index - 1u];
        DWORD bit = 1u << (DWORD)spec->id;
        if ((native_dispatch_installed_mask & bit) == 0u) continue;
        if (!rollback_detour(
            spec->target, spec->signature, spec->minimum_patch_size,
            spec->trampoline_slot)) {
            return FALSE;
        }
        native_dispatch_installed_mask &= ~bit;
        --native_dispatch_installed_count;
    }
    return native_dispatch_installed_count == 0u &&
        native_dispatch_installed_mask == 0u;
}

static BOOL replace_dispatch_slot(void **slot, void *expected, void *replacement)
{
    DWORD old_protect, ignored;
    void *observed;
    if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old_protect)) {
        return FALSE;
    }
    observed = InterlockedCompareExchangePointer(slot, replacement, expected);
    if (!VirtualProtect(slot, sizeof(*slot), old_protect, &ignored)) {
        detour_rollback_failed = TRUE;
        return FALSE;
    }
    return observed == expected;
}

static BOOL body_lifecycle_slots_match(void)
{
    DWORD mode_index, phase;
    if (body_dispatch_state == BODY_DISPATCH_DISABLED) return TRUE;
    for (mode_index = 0u; mode_index < BODY_MODE_COUNT; ++mode_index) {
        const BodyModeLifecycle *mode = &BODY_MODE_LIFECYCLES[mode_index];
        for (phase = 0u; phase < BODY_PHASE_COUNT; ++phase) {
            void **slot = (void **)(ULONG_PTR)(
                mode->vtable + BODY_PHASE_VTABLE_OFFSETS[phase]);
            if (*slot != (void *)(ULONG_PTR)mode->entries[phase]) return FALSE;
        }
    }
    return TRUE;
}

static BOOL rollback_body_lifecycle_interposition(void)
{
    while (body_lifecycle_installed_slots != 0u) {
        DWORD flat = body_lifecycle_installed_slots - 1u;
        DWORD mode_index = flat / BODY_PHASE_COUNT;
        DWORD phase = flat % BODY_PHASE_COUNT;
        const BodyModeLifecycle *mode = &BODY_MODE_LIFECYCLES[mode_index];
        void **slot = (void **)(ULONG_PTR)(
            mode->vtable + BODY_PHASE_VTABLE_OFFSETS[phase]);
        if (!replace_dispatch_slot(
                slot, BODY_PHASE_HOOKS[phase],
                (void *)(ULONG_PTR)mode->entries[phase])) {
            return FALSE;
        }
        --body_lifecycle_installed_slots;
    }
    return TRUE;
}

static BOOL install_body_lifecycle_interposition(void)
{
    DWORD mode_index, phase;
    if (body_dispatch_state == BODY_DISPATCH_DISABLED) return TRUE;
    for (mode_index = 0u; mode_index < BODY_MODE_COUNT; ++mode_index) {
        const BodyModeLifecycle *mode = &BODY_MODE_LIFECYCLES[mode_index];
        for (phase = 0u; phase < BODY_PHASE_COUNT; ++phase) {
            void **slot = (void **)(ULONG_PTR)(
                mode->vtable + BODY_PHASE_VTABLE_OFFSETS[phase]);
            if (!replace_dispatch_slot(
                    slot, (void *)(ULONG_PTR)mode->entries[phase],
                    BODY_PHASE_HOOKS[phase])) {
                if (!rollback_body_lifecycle_interposition()) {
                    detour_rollback_failed = TRUE;
                }
                return FALSE;
            }
            ++body_lifecycle_installed_slots;
        }
    }
    return TRUE;
}

static BOOL install_manager_tick_interposition(void)
{
    if (diagnostic_skip_target == FLIGHT_TICK ||
        diagnostic_skip_manager_tick) return TRUE;
    if (!replace_dispatch_slot(
            MANAGER_TICK_VTABLE_SLOT, manager_tick_original,
            (void *)(ULONG_PTR)&manager_tick_vtable_hook)) return FALSE;
    manager_tick_interposed = TRUE;
    return TRUE;
}

static BOOL ensure_calibration_manager_tick_interposition(void)
{
    void *hook = (void *)(ULONG_PTR)&manager_tick_vtable_hook;
    DWORD observed_address = 0u;
    void *observed;
    if (!read_pointer(
            (DWORD)(ULONG_PTR)MANAGER_TICK_VTABLE_SLOT, 0u,
            &observed_address)) {
        return FALSE;
    }
    observed = (void *)(ULONG_PTR)observed_address;
    if (observed == hook) {
        manager_tick_interposed = TRUE;
        return TRUE;
    }
    if (observed != manager_tick_original ||
        !replace_dispatch_slot(
            MANAGER_TICK_VTABLE_SLOT, manager_tick_original, hook)) {
        return FALSE;
    }
    manager_tick_interposed = TRUE;
    return TRUE;
}

static BOOL install_manager_render_interposition(void)
{
    if (manager_render_interposed) return TRUE;
    if (!replace_dispatch_slot(
            MANAGER_RENDER_VTABLE_SLOT, manager_render_original,
            (void *)(ULONG_PTR)&manager_render_vtable_hook)) return FALSE;
    manager_render_interposed = TRUE;
    return TRUE;
}

static BOOL complete_observer_bootstrap(DWORD expected_manager)
{
    HANDLE controller;
    LONG state;
    if (calibration_observation_only &&
        !calibration_bootstrap_manager_ready(expected_manager)) {
        return FALSE;
    }
    state = InterlockedCompareExchange(&observer_bootstrap_state, 1, 0);
    if (state == 2) return TRUE;
    if (state == 1) {
        return WaitForSingleObject(
                   ready_event, LATE_BOOTSTRAP_COMPLETION_WAIT_MS) ==
                    WAIT_OBJECT_0 &&
            InterlockedCompareExchange(&observer_ready, 0, 0) == 1;
    }
    if (state != 0) return FALSE;
    if (!install_manager_tick_interposition()) {
        InterlockedExchange(&observer_bootstrap_state, -1);
        session_fail("manager_tick_interposition");
        return FALSE;
    }
    controller = CreateThread(
        NULL, 0u, session_controller_thread, NULL, 0u, NULL);
    if (!controller) {
        InterlockedExchange(&observer_bootstrap_state, -1);
        session_fail("session_controller_thread");
        return FALSE;
    }
    CloseHandle(controller);
    InterlockedExchange(&observer_ready, 1);
    if (!SetEvent(ready_event)) {
        InterlockedExchange(&observer_bootstrap_state, -1);
        session_fail("observer_ready_event");
        return FALSE;
    }
    write_marker("LOADED");
    emit_observation_profile();
    emit_natural_session("start", "ACTIVE");
    if (natural_capture_edge &&
        strcmp(natural_capture_edge->id, "startup.login") == 0) {
        emit_natural_transition(natural_capture_edge,
                                mode_transitions[0].caller_site);
    }
    emit_bootstrap_diagnostic();
    flush_trace();
    InterlockedExchange(&observer_bootstrap_state, 2);
    return TRUE;
}

static BOOL install_shadow_render_interposition(void)
{
    if (calibration_observation_only ||
        native_dispatch_target_scoped() ||
        (semantic_observation_only &&
         (semantic_observation_omit_mask & OBSERVE_OMIT_SHADOW_IAT) != 0u)) {
        return TRUE;
    }
    if (shadow_render_interposed) return TRUE;
    if (!replace_dispatch_slot(
            CC_SHADOW_RENDER_IAT, shadow_render_original,
            (void *)(ULONG_PTR)&shadow_render_iat_hook)) return FALSE;
    shadow_render_interposed = TRUE;
    return TRUE;
}

static BOOL rollback_shadow_render_interposition(void)
{
    if (!shadow_render_interposed) return TRUE;
    if (!replace_dispatch_slot(
            CC_SHADOW_RENDER_IAT,
            (void *)(ULONG_PTR)&shadow_render_iat_hook,
            shadow_render_original)) {
        return FALSE;
    }
    shadow_render_interposed = FALSE;
    return TRUE;
}

static BOOL rollback_manager_tick_interposition(void)
{
    BOOL restored = TRUE;
    if (manager_tick_interposed) {
        if (replace_dispatch_slot(
                MANAGER_TICK_VTABLE_SLOT,
                (void *)(ULONG_PTR)&manager_tick_vtable_hook,
                manager_tick_original)) {
            manager_tick_interposed = FALSE;
        } else {
            restored = FALSE;
        }
    }
    if (manager_render_interposed) {
        if (replace_dispatch_slot(
                MANAGER_RENDER_VTABLE_SLOT,
                (void *)(ULONG_PTR)&manager_render_vtable_hook,
                manager_render_original)) {
            manager_render_interposed = FALSE;
        } else {
            restored = FALSE;
        }
    }
    return restored;
}

static BOOL preflight_module_identity(HMODULE *cc_module_out)
{
    char path[MAX_PATH * 2];
    BYTE digest[32];
    DWORD length;
    HMODULE cc_module;
    length = GetModuleFileNameA(NULL, path, sizeof(path));
    if (length == 0u || length >= sizeof(path) ||
        !hash_file(path, digest) ||
        memcmp(digest, EXPECTED_EXE_SHA256, sizeof(digest)) != 0 ||
        memcmp(STARTUP_MODE_ARGUMENT, STARTUP_MODE_ARGUMENT_SIGNATURE,
               sizeof(STARTUP_MODE_ARGUMENT_SIGNATURE)) != 0) return FALSE;
    cc_module = GetModuleHandleA("Cc.dll");
    if (!cc_module) return FALSE;
    length = GetModuleFileNameA(cc_module, path, sizeof(path));
    if (length == 0u || length >= sizeof(path) ||
        !hash_file(path, digest) ||
        memcmp(digest, EXPECTED_CC_SHA256, sizeof(digest)) != 0) return FALSE;
    *cc_module_out = cc_module;
    return TRUE;
}

static BOOL preflight_shadow_render_import(HMODULE cc_module)
{
    void *resolved = (void *)(ULONG_PTR)GetProcAddress(
        cc_module, "?Render@CcShadow@@QAEXPAVCcSrtNode@@@Z");
    if (!resolved || *CC_SHADOW_RENDER_IAT != resolved) return FALSE;
    shadow_render_original = resolved;
    shadow_camera_render_target = (BYTE *)(ULONG_PTR)GetProcAddress(
        cc_module, "?Render@CcCamera@@QAEX_N@Z");
    if (!shadow_camera_render_target ||
        shadow_camera_render_target != (BYTE *)cc_module + 0x1d720u ||
        memcmp(shadow_camera_render_target, SHADOW_CAMERA_RENDER_SIGNATURE,
               sizeof(SHADOW_CAMERA_RENDER_SIGNATURE)) != 0) return FALSE;
    shadow_render_room_target = (BYTE *)(ULONG_PTR)GetProcAddress(
        cc_module,
        "?RenderRoom@CcCamera@@IAEXPAVCcRoom@@PAVCcScreenClip@@HH@Z");
    if (!shadow_render_room_target ||
        shadow_render_room_target != (BYTE *)cc_module + 0x1e390u ||
        memcmp(shadow_render_room_target, SHADOW_RENDER_ROOM_SIGNATURE,
               sizeof(SHADOW_RENDER_ROOM_SIGNATURE)) != 0) return FALSE;
    shadow_visible_objects_target = (BYTE *)(ULONG_PTR)GetProcAddress(
        cc_module,
        "?AddVisibleObjectsToRenderList@CcRoom@@IAEXPAVCcCamera@@"
        "AAVCcRenderList@@PAVCcObject@@@Z");
    if (!shadow_visible_objects_target ||
        shadow_visible_objects_target != (BYTE *)cc_module + 0x1fd00u ||
        memcmp(shadow_visible_objects_target, SHADOW_VISIBLE_OBJECTS_SIGNATURE,
               sizeof(SHADOW_VISIBLE_OBJECTS_SIGNATURE)) != 0) return FALSE;
    shadow_visible_polygons_target = (BYTE *)(ULONG_PTR)GetProcAddress(
        cc_module,
        "?AddVisiblePolygonsToRenderList@CcObject@@IAEXPAVCcCamera@@"
        "AAVCcRenderList@@_N@Z");
    if (!shadow_visible_polygons_target ||
        shadow_visible_polygons_target != (BYTE *)cc_module + 0x1f5d0u ||
        memcmp(shadow_visible_polygons_target,
               SHADOW_VISIBLE_POLYGONS_SIGNATURE,
               sizeof(SHADOW_VISIBLE_POLYGONS_SIGNATURE)) != 0) return FALSE;
    shadow_polygon_render_target = (BYTE *)(ULONG_PTR)GetProcAddress(
        cc_module, "?Render@CcObjPolygon@@IAEXPAVCcCamera@@H@Z");
    if (!shadow_polygon_render_target ||
        shadow_polygon_render_target != (BYTE *)cc_module + 0x1a740u ||
        memcmp(shadow_polygon_render_target, SHADOW_POLYGON_RENDER_SIGNATURE,
               sizeof(SHADOW_POLYGON_RENDER_SIGNATURE)) != 0) return FALSE;
    shadow_world_relation_target = (BYTE *)(ULONG_PTR)GetProcAddress(
        cc_module, "?GetWorldRelation@CcSrtNode@@QAE_NXZ");
    if (!shadow_world_relation_target ||
        shadow_world_relation_target != (BYTE *)cc_module + 0xf020u ||
        memcmp(shadow_world_relation_target, SHADOW_WORLD_RELATION_SIGNATURE,
               sizeof(SHADOW_WORLD_RELATION_SIGNATURE)) != 0) return FALSE;
    shadow_rotation_setter_target = (BYTE *)(ULONG_PTR)GetProcAddress(
        cc_module, "?RotateByZAxis@CcMatrixRot@@QAEXM@Z");
    if (!shadow_rotation_setter_target ||
        shadow_rotation_setter_target != (BYTE *)cc_module + 0x2cec0u ||
        memcmp(shadow_rotation_setter_target,
               SHADOW_ROTATION_SETTER_SIGNATURE,
               sizeof(SHADOW_ROTATION_SETTER_SIGNATURE)) != 0) return FALSE;
    return TRUE;
}

static BOOL resolve_framebuffer_exports(HMODULE module)
{
    framebuffer_export_error = NULL;
    read_screen_export = (ReadScreenFunction)(ULONG_PTR)GetProcAddress(
        module, "?ReadScreen@GtDevice@@UAEPAVGtImage@@PAV2@@Z");
    image_get_pointer = (ImagePointerFunction)(ULONG_PTR)GetProcAddress(
        module, "?GetImagePtr@GtImage@@QAEPAXH@Z");
    image_get_width = (ImageLevelIntFunction)(ULONG_PTR)GetProcAddress(
        module, "?GetWidth@GtImage@@QAEHH@Z");
    image_get_height = (ImageLevelIntFunction)(ULONG_PTR)GetProcAddress(
        module, "?GetHeight@GtImage@@QAEHH@Z");
    image_get_pitch = (ImageLevelIntFunction)(ULONG_PTR)GetProcAddress(
        module, "?GetPitch@GtImage@@QAEHH@Z");
    image_get_size = (ImageLevelIntFunction)(ULONG_PTR)GetProcAddress(
        module, "?GetImageSize@GtImage@@QAEHH@Z");
    image_get_pixel_size = (ImageIntFunction)(ULONG_PTR)GetProcAddress(
        module, "?GetPixelSize@GtImage@@QAEHXZ");
    image_get_format = (ImageIntFunction)(ULONG_PTR)GetProcAddress(
        module, "?GetFormat@GtImage@@QAE?AW4GT_FMT@@XZ");
    image_destructor = (ImageDestructorFunction)(ULONG_PTR)GetProcAddress(
        module, "??1GtImage@@QAE@XZ");
    if (!read_screen_export) framebuffer_export_error = "export_read_screen";
    else if (!image_get_pointer) framebuffer_export_error = "export_image_pointer";
    else if (!image_get_width) framebuffer_export_error = "export_image_width";
    else if (!image_get_height) framebuffer_export_error = "export_image_height";
    else if (!image_get_pitch) framebuffer_export_error = "export_image_pitch";
    else if (!image_get_size) framebuffer_export_error = "export_image_size";
    else if (!image_get_pixel_size) framebuffer_export_error = "export_pixel_size";
    else if (!image_get_format) framebuffer_export_error = "export_image_format";
    else if (!image_destructor) framebuffer_export_error = "export_image_destructor";
    return framebuffer_export_error == NULL;
}

static BOOL preflight_import_hooks(void)
{
    HMODULE runtime = GetModuleHandleA("msvcrt.dll");
    RandFunction runtime_rand;
    SrandFunction runtime_srand;
    if (!runtime) return FALSE;
    runtime_rand = (RandFunction)(ULONG_PTR)GetProcAddress(runtime, "rand");
    runtime_srand = (SrandFunction)(ULONG_PTR)GetProcAddress(runtime, "srand");
    if (!runtime_rand || !runtime_srand ||
        *RAND_IAT != (void *)(ULONG_PTR)runtime_rand ||
        *SRAND_IAT != (void *)(ULONG_PTR)runtime_srand) return FALSE;
    original_rand = runtime_rand;
    original_srand = runtime_srand;
    return TRUE;
}

static BOOL write_import_slot(void **slot, void *value)
{
    DWORD old_protect, ignored;
    if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old_protect)) {
        return FALSE;
    }
    *slot = value;
    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(*slot));
    if (!VirtualProtect(slot, sizeof(*slot), old_protect, &ignored)) {
        detour_rollback_failed = TRUE;
        return FALSE;
    }
    return TRUE;
}

static BOOL install_import_hooks(void)
{
    if (!write_import_slot(RAND_IAT, (void *)(ULONG_PTR)observer_rand)) {
        return FALSE;
    }
    if (!write_import_slot(SRAND_IAT, (void *)(ULONG_PTR)observer_srand)) {
        if (!write_import_slot(RAND_IAT, (void *)(ULONG_PTR)original_rand)) {
            detour_rollback_failed = TRUE;
        }
        return FALSE;
    }
    return TRUE;
}

static BOOL install_observer_import_hooks(void)
{
    if (native_dispatch_target_scoped()) return TRUE;
    return install_import_hooks();
}

static BOOL rollback_import_hooks(void)
{
    BOOL restored = TRUE;
    if (original_srand && *SRAND_IAT == (void *)(ULONG_PTR)observer_srand) {
        if (!write_import_slot(
                SRAND_IAT, (void *)(ULONG_PTR)original_srand)) {
            restored = FALSE;
        }
    }
    if (original_rand && *RAND_IAT == (void *)(ULONG_PTR)observer_rand) {
        if (!write_import_slot(RAND_IAT, (void *)(ULONG_PTR)original_rand)) {
            restored = FALSE;
        }
    }
    return restored;
}

static BOOL all_hook_signatures_match(void)
{
    return native_dispatch_signatures_match() &&
        *MANAGER_RENDER_VTABLE_SLOT == manager_render_original &&
        *MANAGER_TICK_VTABLE_SLOT == manager_tick_original &&
        *CC_SHADOW_RENDER_IAT == shadow_render_original &&
        body_lifecycle_slots_match() &&
        memcmp(MODE_SET, MODE_SET_SIGNATURE,
               sizeof(MODE_SET_SIGNATURE)) == 0 &&
        memcmp(QUEUE_MODE, QUEUE_MODE_SIGNATURE,
               sizeof(QUEUE_MODE_SIGNATURE)) == 0 &&
        memcmp(FLIGHT_TARGET, FLIGHT_TARGET_SIGNATURE,
               sizeof(FLIGHT_TARGET_SIGNATURE)) == 0 &&
        memcmp(EXHIBITION_CALLBACK, EXHIBITION_CALLBACK_SIGNATURE,
               sizeof(EXHIBITION_CALLBACK_SIGNATURE)) == 0 &&
        memcmp(UDSP_DISPATCH, UDSP_DISPATCH_SIGNATURE,
               sizeof(UDSP_DISPATCH_SIGNATURE)) == 0 &&
        memcmp(POSITION_CHARACTER_WRITE, POSITION_CHARACTER_WRITE_SIGNATURE,
               sizeof(POSITION_CHARACTER_WRITE_SIGNATURE)) == 0 &&
        memcmp(POSITION_CHARACTER_RESOLVE,
               POSITION_CHARACTER_RESOLVE_SIGNATURE,
               sizeof(POSITION_CHARACTER_RESOLVE_SIGNATURE)) == 0 &&
        memcmp(UDSP_ROOT_UPDATE, UDSP_ROOT_UPDATE_SIGNATURE,
               sizeof(UDSP_ROOT_UPDATE_SIGNATURE)) == 0 &&
        memcmp(UDSP_ROOT_START, UDSP_ROOT_START_SIGNATURE,
               sizeof(UDSP_ROOT_START_SIGNATURE)) == 0 &&
        memcmp(SCENE_DISPATCH_BARN, SCENE_DISPATCH_BARN_SIGNATURE,
               sizeof(SCENE_DISPATCH_BARN_SIGNATURE)) == 0 &&
        memcmp(SCENE_DISPATCH_GROUND, SCENE_DISPATCH_GROUND_SIGNATURE,
               sizeof(SCENE_DISPATCH_GROUND_SIGNATURE)) == 0 &&
        memcmp(SCENE_DISPATCH_FLIGHT, SCENE_DISPATCH_FLIGHT_SIGNATURE,
               sizeof(SCENE_DISPATCH_FLIGHT_SIGNATURE)) == 0 &&
        memcmp(FLIGHT_TICK, TICK_SIGNATURE, sizeof(TICK_SIGNATURE)) == 0 &&
        memcmp(LOGIN_TICK, LOGIN_TICK_SIGNATURE,
               sizeof(LOGIN_TICK_SIGNATURE)) == 0 &&
        memcmp(MODE_LIFECYCLE_RETURN, MODE_LIFECYCLE_SIGNATURE,
               sizeof(MODE_LIFECYCLE_SIGNATURE)) == 0 &&
        memcmp(PARTICLE_EMITTER_TICK, PARTICLE_EMITTER_TICK_SIGNATURE,
               sizeof(PARTICLE_EMITTER_TICK_SIGNATURE)) == 0 &&
        memcmp(PARTICLE_RESET, PARTICLE_RESET_SIGNATURE,
               sizeof(PARTICLE_RESET_SIGNATURE)) == 0 &&
        memcmp(PARTICLE_PLACE, PARTICLE_PLACE_SIGNATURE,
               sizeof(PARTICLE_PLACE_SIGNATURE)) == 0 &&
        memcmp(RENDER_LIST_DISPATCH, RENDER_LIST_DISPATCH_SIGNATURE,
               sizeof(RENDER_LIST_DISPATCH_SIGNATURE)) == 0 &&
        memcmp(AIRPLANE_PRESENTATION, AIRPLANE_PRESENTATION_SIGNATURE,
               sizeof(AIRPLANE_PRESENTATION_SIGNATURE)) == 0 &&
        memcmp(BARN_FLYAWAY, BARN_FLYAWAY_SIGNATURE,
               sizeof(BARN_FLYAWAY_SIGNATURE)) == 0 &&
        memcmp(BARN_INPUT_DISPATCH, BARN_INPUT_DISPATCH_SIGNATURE,
               sizeof(BARN_INPUT_DISPATCH_SIGNATURE)) == 0 &&
        memcmp(BARN_ESCAPE_LOOKUP, BARN_ESCAPE_LOOKUP_SIGNATURE,
               sizeof(BARN_ESCAPE_LOOKUP_SIGNATURE)) == 0 &&
        memcmp(BARN_ESCAPE_ACTION, BARN_ESCAPE_ACTION_SIGNATURE,
               sizeof(BARN_ESCAPE_ACTION_SIGNATURE)) == 0 &&
        memcmp(MYGGHANGET_START_ENGINE_GATE,
               MYGGHANGET_START_ENGINE_GATE_SIGNATURE,
               sizeof(MYGGHANGET_START_ENGINE_GATE_SIGNATURE)) == 0 &&
        memcmp(MYGGHANGET_DIRECT_DEPARTURE,
               MYGGHANGET_DIRECT_DEPARTURE_SIGNATURE,
               sizeof(MYGGHANGET_DIRECT_DEPARTURE_SIGNATURE)) == 0 &&
        memcmp(FLIGHT_RENDER_LIST_REGISTRATION,
               FLIGHT_RENDER_LIST_REGISTRATION_SIGNATURE,
               sizeof(FLIGHT_RENDER_LIST_REGISTRATION_SIGNATURE)) == 0 &&
        memcmp(FLIGHT_RENDER_LIST_USE,
               FLIGHT_RENDER_LIST_USE_SIGNATURE,
               sizeof(FLIGHT_RENDER_LIST_USE_SIGNATURE)) == 0 &&
        memcmp(CONTROLS_PRE, CONTROLS_PRE_SIGNATURE,
               sizeof(CONTROLS_PRE_SIGNATURE)) == 0 &&
        memcmp(CONTROLS_POST, CONTROLS_POST_SIGNATURE,
               sizeof(CONTROLS_POST_SIGNATURE)) == 0 &&
        memcmp(FLIGHT_STEP_ENTRY, ENTRY_SIGNATURE, sizeof(ENTRY_SIGNATURE)) == 0 &&
        memcmp(FLIGHT_STEP_LEAVE, LEAVE_SIGNATURE, sizeof(LEAVE_SIGNATURE)) == 0 &&
        memcmp(COLLISION_ENTRY, COLLISION_SIGNATURE,
               sizeof(COLLISION_SIGNATURE)) == 0 &&
        memcmp(COLLISION_COMMIT, COLLISION_COMMIT_SIGNATURE,
               sizeof(COLLISION_COMMIT_SIGNATURE)) == 0 &&
        memcmp(CAMERA_COMMIT, CAMERA_COMMIT_SIGNATURE,
               sizeof(CAMERA_COMMIT_SIGNATURE)) == 0 &&
        memcmp(RENDER_FINAL, RENDER_FINAL_SIGNATURE,
               sizeof(RENDER_FINAL_SIGNATURE)) == 0 &&
        memcmp(FUEL_DEPLETION, FUEL_DEPLETION_SIGNATURE,
               sizeof(FUEL_DEPLETION_SIGNATURE)) == 0 &&
        memcmp(FUEL_POST_CONSUME, FUEL_POST_CONSUME_SIGNATURE,
               sizeof(FUEL_POST_CONSUME_SIGNATURE)) == 0 &&
        memcmp(CONTACT_SITE, CONTACT_SIGNATURE, sizeof(CONTACT_SIGNATURE)) == 0 &&
        memcmp(DAMAGE_EFFECTIVE, DAMAGE_EFFECTIVE_SIGNATURE,
               sizeof(DAMAGE_EFFECTIVE_SIGNATURE)) == 0 &&
        memcmp(DAMAGE_POST, DAMAGE_POST_SIGNATURE,
               sizeof(DAMAGE_POST_SIGNATURE)) == 0 &&
        memcmp(DAMAGE_NONTERMINAL, DAMAGE_NONTERMINAL_SIGNATURE,
               sizeof(DAMAGE_NONTERMINAL_SIGNATURE)) == 0 &&
        memcmp(TERMINAL_CRASH, TERMINAL_CRASH_SIGNATURE,
               sizeof(TERMINAL_CRASH_SIGNATURE)) == 0 &&
        memcmp(TERRAIN_RESULT_CRASH, TERRAIN_RESULT_CRASH_SIGNATURE,
               sizeof(TERRAIN_RESULT_CRASH_SIGNATURE)) == 0 &&
        memcmp(TERRAIN_RESULT_RENDER, TERRAIN_RESULT_RENDER_SIGNATURE,
               sizeof(TERRAIN_RESULT_RENDER_SIGNATURE)) == 0;
}

static DWORD parse_record_limit(void)
{
    char text[32];
    DWORD length = GetEnvironmentVariableA(
        "MIEL_OBSERVER_MAX_RECORDS", text, sizeof(text));
    DWORD value = 0u;
    DWORD index;
    if (length == 0u || length >= sizeof(text)) return DEFAULT_RECORD_LIMIT;
    for (index = 0u; index < length; ++index) {
        if (text[index] < '0' || text[index] > '9') return DEFAULT_RECORD_LIMIT;
        if (value > (MAX_RECORD_LIMIT / 10u)) return MAX_RECORD_LIMIT;
        value = value * 10u + (DWORD)(text[index] - '0');
        if (value > MAX_RECORD_LIMIT) return MAX_RECORD_LIMIT;
    }
    return value == 0u ? DEFAULT_RECORD_LIMIT : value;
}

__declspec(dllexport) DWORD WINAPI MielObserverInitialize(LPVOID unused)
{
    HMODULE pinned_module = NULL;
    HMODULE cc_module = NULL;
    char log_path[MAX_PATH * 2];
    char scenario_path[MAX_PATH * 2];
    char scenario_hash_text[65];
    char initial_user_hash_text[65];
    BYTE scenario_hash[32];
    BOOL rollback_ok = TRUE;
    (void)unused;

    if (InterlockedCompareExchange(&initialization_started, 1, 0) != 0) {
        return 0u;
    }
    InitializeCriticalSection(&trace_lock);
    trace_lock_ready = TRUE;
    trace_record_limit = parse_record_limit();
    {
        char diagnostics[2] = {0};
        bootstrap_diagnostics_enabled =
            GetEnvironmentVariableA("MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS",
                                    diagnostics, sizeof(diagnostics)) == 1u &&
            diagnostics[0] == '1';
    }
    if (!get_required_environment("MIEL_OBSERVER_LOG", log_path,
                                  sizeof(log_path))) return 0u;
    trace_file = CreateFileA(log_path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (trace_file == INVALID_HANDLE_VALUE) return 0u;
    {
        char calibration[2] = {0};
        DWORD calibration_length = GetEnvironmentVariableA(
            "MIEL_OBSERVER_CALIBRATE_INITIAL_STATE", calibration,
            sizeof(calibration));
        if (calibration_length == 0u) {
            runtime_state_calibration = FALSE;
        } else if (calibration_length == 1u && calibration[0] == '1') {
            runtime_state_calibration = TRUE;
        } else {
            session_fail("runtime_initial_state_calibration_environment");
            return 0u;
        }
    }
    if (bootstrap_diagnostics_enabled) {
        diagnostic_exception_handler = AddVectoredExceptionHandler(
            1u, record_bootstrap_exception);
        if (!diagnostic_exception_handler) {
            session_fail("exception_diagnostic_contract");
            return 0u;
        }
    }
    if (!configure_native_capture_driver_bootstrap()) {
        session_fail("native_capture_driver_bootstrap_environment");
        return 0u;
    }
    if (!get_required_environment("MIEL_OBSERVER_SCENARIO", scenario_path,
                                  sizeof(scenario_path)) ||
        !get_required_environment("MIEL_OBSERVER_SCENARIO_SHA256",
                                  scenario_hash_text,
                                  sizeof(scenario_hash_text)) ||
        !get_required_environment("MIEL_OBSERVER_INITIAL_USER_SHA256",
                                  initial_user_hash_text,
                                  sizeof(initial_user_hash_text)) ||
        !get_required_environment("MIEL_OBSERVER_FRAME", frame_prefix,
                                  sizeof(frame_prefix))) {
        session_fail("environment_contract");
        return 0u;
    }
    if (!decode_sha256(scenario_hash_text, scenario_hash)) {
        session_fail("scenario_hash_encoding");
        return 0u;
    }
    if (!decode_sha256(initial_user_hash_text, initial_user_sha256)) {
        session_fail("initial_user_hash_encoding");
        return 0u;
    }
    if (!parse_replay_file(scenario_path, scenario_hash)) {
        session_fail("scenario_replay_contract");
        return 0u;
    }
    if (runtime_state_calibration && replay_runtime_state_bound) {
        session_fail("runtime_initial_state_calibration_requires_unbound_replay");
        return 0u;
    }
    if (!create_completion_events()) {
        session_fail("completion_event_contract");
        return 0u;
    }
    if (!start_replay_focus_scheduler()) {
        session_fail("focus_timeline_scheduler_contract");
        return 0u;
    }
    if (!data_user_fixture_ready()) {
        session_fail("initial_user_fixture_contract");
        return 0u;
    }
    if (!preflight_module_identity(&cc_module)) {
        session_fail("module_identity_contract");
        return 0u;
    }
    if (!resolve_framebuffer_exports(cc_module)) {
        session_fail(framebuffer_export_error ? framebuffer_export_error :
                     "framebuffer_export_contract");
        return 0u;
    }
    if (!preflight_import_hooks()) {
        session_fail("rng_import_contract");
        return 0u;
    }
    if (!preflight_shadow_render_import(cc_module)) {
        session_fail("shadow_render_import_contract");
        return 0u;
    }
    if (!configure_body_dispatch() ||
        !configure_scene_dispatch_observation() ||
        !configure_native_dispatch_producer() ||
        !configure_native_capture_driver() ||
        !configure_diagnostic_skip_target() ||
        !configure_diagnostic_profile() ||
        !configure_natural_transition_capture() ||
        !configure_observation_profile()) {
        session_fail("diagnostic_hook_policy_contract");
        return 0u;
    }
    if (natural_capture_edge && !establish_natural_observer_identity()) {
        session_fail("natural_observer_identity_contract");
        return 0u;
    }
    if (!all_hook_signatures_match()) {
        session_fail("hook_signature_contract");
        return 0u;
    }
    /* Every interposition below can leave a live call edge into this image if
     * Windows refuses a protection transition during recovery.  Pin before
     * the first write so a hard-failed initialization can never unload code
     * still reachable from the projector. */
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_PIN,
            (LPCSTR)(ULONG_PTR)&MielObserverInitialize, &pinned_module)) {
        session_fail("observer_pin_contract");
        return 0u;
    }
    if (!install_observer_import_hooks()) goto install_failed;
    /* Audio completion / animation-cadence observations are an optional,
     * scenario-bounded media-semantics channel that is deliberately outside
     * the reviewed flight-parity receipt contract (it can never promote
     * parity). Bind the sites best-effort: install_detour only patches a site
     * whose pinned signature matches, so a mismatch leaves the original code
     * untouched, the trampoline NULL and the hook uncalled. A site that
     * cannot be bound therefore skips the channel instead of preventing the
     * observer from loading and bootstrapping the game. */
    if (scenario_bounded_observation) {
        (void)install_detour(AUDIO_START, AUDIO_START_SIGNATURE,
                             sizeof(AUDIO_START_SIGNATURE), audio_start_hook,
                             &audio_start_trampoline);
        (void)install_detour(AUDIO_POLL, AUDIO_POLL_SIGNATURE,
                             sizeof(AUDIO_POLL_SIGNATURE), audio_poll_hook,
                             &audio_poll_trampoline);
    }
    if ((diagnostic_direct_login_tick &&
         !install_detour(LOGIN_TICK, LOGIN_TICK_SIGNATURE,
                         sizeof(LOGIN_TICK_SIGNATURE), login_tick_hook,
                         &login_tick_trampoline)) ||
        !install_detour(MODE_SET, MODE_SET_SIGNATURE, 8u, mode_set_hook,
                        &mode_set_trampoline) ||
        !install_detour(QUEUE_MODE, QUEUE_MODE_SIGNATURE,
                        sizeof(QUEUE_MODE_SIGNATURE), queue_mode_hook,
                        &queue_mode_trampoline) ||
        !install_detour(FLIGHT_TARGET, FLIGHT_TARGET_SIGNATURE,
                        sizeof(FLIGHT_TARGET_SIGNATURE), flight_target_hook,
                        &flight_target_trampoline) ||
        !install_detour(EXHIBITION_CALLBACK, EXHIBITION_CALLBACK_SIGNATURE,
                        sizeof(EXHIBITION_CALLBACK_SIGNATURE),
                        exhibition_callback_hook,
                        &exhibition_callback_trampoline) ||
        !install_detour(UDSP_DISPATCH, UDSP_DISPATCH_SIGNATURE,
                        sizeof(UDSP_DISPATCH_SIGNATURE), udsp_dispatch_hook,
                        &udsp_dispatch_trampoline) ||
        !install_detour(POSITION_CHARACTER_WRITE,
                        POSITION_CHARACTER_WRITE_SIGNATURE,
                        sizeof(POSITION_CHARACTER_WRITE_SIGNATURE),
                        position_character_write_hook,
                        &position_character_write_trampoline) ||
        !install_detour(PARTICLE_EMITTER_TICK,
                        PARTICLE_EMITTER_TICK_SIGNATURE,
                        sizeof(PARTICLE_EMITTER_TICK_SIGNATURE),
                        particle_emitter_tick_hook,
                        &particle_emitter_tick_trampoline) ||
        !install_detour(PARTICLE_RESET, PARTICLE_RESET_SIGNATURE,
                        sizeof(PARTICLE_RESET_SIGNATURE), particle_reset_hook,
                        &particle_reset_trampoline) ||
        !install_detour(PARTICLE_PLACE, PARTICLE_PLACE_SIGNATURE,
                        sizeof(PARTICLE_PLACE_SIGNATURE), particle_place_hook,
                        &particle_place_trampoline) ||
        !install_detour(RENDER_LIST_DISPATCH,
                        RENDER_LIST_DISPATCH_SIGNATURE,
                        sizeof(RENDER_LIST_DISPATCH_SIGNATURE),
                        render_list_dispatch_hook,
                        &render_list_dispatch_trampoline) ||
        !install_detour(AIRPLANE_PRESENTATION,
                        AIRPLANE_PRESENTATION_SIGNATURE,
                        sizeof(AIRPLANE_PRESENTATION_SIGNATURE),
                        airplane_presentation_hook,
                        &airplane_presentation_trampoline) ||
        !install_detour(shadow_camera_render_target,
                        SHADOW_CAMERA_RENDER_SIGNATURE,
                        sizeof(SHADOW_CAMERA_RENDER_SIGNATURE),
                        shadow_camera_render_hook,
                        &shadow_camera_render_trampoline) ||
        !install_detour(shadow_render_room_target,
                        SHADOW_RENDER_ROOM_SIGNATURE,
                        sizeof(SHADOW_RENDER_ROOM_SIGNATURE),
                        shadow_render_room_hook,
                        &shadow_render_room_trampoline) ||
        !install_detour(shadow_visible_objects_target,
                        SHADOW_VISIBLE_OBJECTS_SIGNATURE,
                        sizeof(SHADOW_VISIBLE_OBJECTS_SIGNATURE),
                        shadow_visible_objects_hook,
                        &shadow_visible_objects_trampoline) ||
        !install_detour(shadow_visible_polygons_target,
                        SHADOW_VISIBLE_POLYGONS_SIGNATURE,
                        sizeof(SHADOW_VISIBLE_POLYGONS_SIGNATURE),
                        shadow_visible_polygons_hook,
                        &shadow_visible_polygons_trampoline) ||
        !install_detour(shadow_polygon_render_target,
                        SHADOW_POLYGON_RENDER_SIGNATURE,
                        sizeof(SHADOW_POLYGON_RENDER_SIGNATURE),
                        shadow_polygon_render_hook,
                        &shadow_polygon_render_trampoline) ||
        !install_detour(shadow_world_relation_target,
                        SHADOW_WORLD_RELATION_SIGNATURE,
                        sizeof(SHADOW_WORLD_RELATION_SIGNATURE),
                        shadow_world_relation_hook,
                        &shadow_world_relation_trampoline) ||
        !install_detour(shadow_rotation_setter_target,
                        SHADOW_ROTATION_SETTER_SIGNATURE,
                        sizeof(SHADOW_ROTATION_SETTER_SIGNATURE),
                        shadow_rotation_setter_hook,
                        &shadow_rotation_setter_trampoline) ||
        !install_detour(CONTROLS_PRE, CONTROLS_PRE_SIGNATURE,
                        sizeof(CONTROLS_PRE_SIGNATURE), controls_pre_hook,
                        &controls_pre_trampoline) ||
        !install_detour(CONTROLS_POST, CONTROLS_POST_SIGNATURE,
                        sizeof(CONTROLS_POST_SIGNATURE), controls_post_hook,
                        &controls_post_trampoline) ||
        !install_detour(FLIGHT_STEP_ENTRY, ENTRY_SIGNATURE,
                        sizeof(ENTRY_SIGNATURE), flight_entry_hook,
                        &flight_entry_trampoline) ||
        !install_detour(FLIGHT_STEP_LEAVE, LEAVE_SIGNATURE,
                        sizeof(LEAVE_SIGNATURE), flight_leave_hook,
                        &flight_leave_trampoline) ||
        !install_detour(COLLISION_ENTRY, COLLISION_SIGNATURE,
                        sizeof(COLLISION_SIGNATURE), collision_entry_hook,
                        &collision_entry_trampoline) ||
        !install_detour(COLLISION_COMMIT, COLLISION_COMMIT_SIGNATURE,
                        sizeof(COLLISION_COMMIT_SIGNATURE), collision_commit_hook,
                        &collision_commit_trampoline) ||
        !install_detour(CAMERA_COMMIT, CAMERA_COMMIT_SIGNATURE,
                        sizeof(CAMERA_COMMIT_SIGNATURE), camera_commit_hook,
                        &camera_commit_trampoline) ||
        !install_detour(RENDER_FINAL, RENDER_FINAL_SIGNATURE,
                        sizeof(RENDER_FINAL_SIGNATURE), render_final_hook,
                        &render_final_trampoline) ||
        !install_detour(FUEL_DEPLETION, FUEL_DEPLETION_SIGNATURE,
                        sizeof(FUEL_DEPLETION_SIGNATURE), fuel_depletion_hook,
                        &fuel_depletion_trampoline) ||
        !install_detour(FUEL_POST_CONSUME, FUEL_POST_CONSUME_SIGNATURE,
                        sizeof(FUEL_POST_CONSUME_SIGNATURE),
                        fuel_post_consume_hook, &fuel_post_consume_trampoline) ||
        !install_detour(CONTACT_SITE, CONTACT_SIGNATURE,
                        sizeof(CONTACT_SIGNATURE), contact_hook,
                        &contact_trampoline) ||
        !install_detour(DAMAGE_EFFECTIVE, DAMAGE_EFFECTIVE_SIGNATURE,
                        sizeof(DAMAGE_EFFECTIVE_SIGNATURE),
                        damage_effective_hook, &damage_effective_trampoline) ||
        !install_detour(DAMAGE_POST, DAMAGE_POST_SIGNATURE,
                        sizeof(DAMAGE_POST_SIGNATURE), damage_post_hook,
                        &damage_post_trampoline) ||
        !install_detour(DAMAGE_NONTERMINAL, DAMAGE_NONTERMINAL_SIGNATURE,
                        sizeof(DAMAGE_NONTERMINAL_SIGNATURE),
                        damage_nonterminal_hook,
                        &damage_nonterminal_trampoline) ||
        !install_detour(TERMINAL_CRASH, TERMINAL_CRASH_SIGNATURE,
                        sizeof(TERMINAL_CRASH_SIGNATURE), terminal_crash_hook,
                        &terminal_crash_trampoline) ||
        !install_detour(TERRAIN_RESULT_CRASH, TERRAIN_RESULT_CRASH_SIGNATURE,
                        sizeof(TERRAIN_RESULT_CRASH_SIGNATURE),
                        terrain_result_crash_hook,
                        &terrain_result_crash_trampoline) ||
        !install_detour(TERRAIN_RESULT_RENDER, TERRAIN_RESULT_RENDER_SIGNATURE,
                        sizeof(TERRAIN_RESULT_RENDER_SIGNATURE),
                        terrain_result_render_hook,
                        &terrain_result_render_trampoline)) goto install_failed;
    if (scene_dispatch_observation_enabled &&
        (!install_detour(SCENE_DISPATCH_GROUND,
                         SCENE_DISPATCH_GROUND_SIGNATURE, 5u,
                         scene_dispatch_ground_hook,
                         &scene_dispatch_ground_trampoline) ||
         !install_detour(SCENE_DISPATCH_BARN,
                         SCENE_DISPATCH_BARN_SIGNATURE, 6u,
                         scene_dispatch_barn_hook,
                         &scene_dispatch_barn_trampoline) ||
         !install_detour(SCENE_DISPATCH_FLIGHT,
                         SCENE_DISPATCH_FLIGHT_SIGNATURE, 6u,
                         scene_dispatch_flight_hook,
                         &scene_dispatch_flight_trampoline) ||
         !install_detour(UDSP_ROOT_START, UDSP_ROOT_START_SIGNATURE, 5u,
                         udsp_root_start_hook,
                         &udsp_root_start_trampoline) ||
         !install_detour(UDSP_ROOT_UPDATE, UDSP_ROOT_UPDATE_SIGNATURE, 6u,
                         udsp_root_update_hook,
                         &udsp_root_update_trampoline))) goto install_failed;
    if (!install_native_dispatch_detours()) goto install_failed;
    if (!install_body_lifecycle_interposition()) goto install_failed;
    if (!install_shadow_render_interposition()) goto install_failed;

    if (calibration_observation_only &&
        !calibration_bootstrap_manager_ready(0u)) {
        HANDLE retry = CreateThread(
            NULL, 0u, late_bootstrap_retry_thread, NULL, 0u, NULL);
        if (!retry) goto install_failed;
        CloseHandle(retry);
    } else if (!complete_observer_bootstrap(0u)) {
        goto install_failed;
    }
    return 1u;

install_failed:
#define rollback_detour(target, original, stolen, trampoline) \
    rollback_detour_accumulating( \
        &rollback_ok, target, original, stolen, trampoline)
    if (!rollback_manager_tick_interposition()) rollback_ok = FALSE;
    if (!rollback_shadow_render_interposition()) rollback_ok = FALSE;
    if (!rollback_body_lifecycle_interposition()) rollback_ok = FALSE;
    if (!rollback_native_dispatch_detours()) rollback_ok = FALSE;
    rollback_detour(UDSP_ROOT_UPDATE, UDSP_ROOT_UPDATE_SIGNATURE, 6u,
                    &udsp_root_update_trampoline);
    rollback_detour(UDSP_ROOT_START, UDSP_ROOT_START_SIGNATURE, 5u,
                    &udsp_root_start_trampoline);
    rollback_detour(SCENE_DISPATCH_FLIGHT,
                    SCENE_DISPATCH_FLIGHT_SIGNATURE, 6u,
                    &scene_dispatch_flight_trampoline);
    rollback_detour(SCENE_DISPATCH_BARN,
                    SCENE_DISPATCH_BARN_SIGNATURE, 6u,
                    &scene_dispatch_barn_trampoline);
    rollback_detour(SCENE_DISPATCH_GROUND,
                    SCENE_DISPATCH_GROUND_SIGNATURE, 5u,
                    &scene_dispatch_ground_trampoline);
    rollback_detour(TERRAIN_RESULT_RENDER, TERRAIN_RESULT_RENDER_SIGNATURE,
                    sizeof(TERRAIN_RESULT_RENDER_SIGNATURE),
                    &terrain_result_render_trampoline);
    rollback_detour(TERRAIN_RESULT_CRASH, TERRAIN_RESULT_CRASH_SIGNATURE,
                    sizeof(TERRAIN_RESULT_CRASH_SIGNATURE),
                    &terrain_result_crash_trampoline);
    rollback_detour(TERMINAL_CRASH, TERMINAL_CRASH_SIGNATURE,
                    sizeof(TERMINAL_CRASH_SIGNATURE),
                    &terminal_crash_trampoline);
    rollback_detour(DAMAGE_NONTERMINAL, DAMAGE_NONTERMINAL_SIGNATURE,
                    sizeof(DAMAGE_NONTERMINAL_SIGNATURE),
                    &damage_nonterminal_trampoline);
    rollback_detour(DAMAGE_POST, DAMAGE_POST_SIGNATURE,
                    sizeof(DAMAGE_POST_SIGNATURE), &damage_post_trampoline);
    rollback_detour(DAMAGE_EFFECTIVE, DAMAGE_EFFECTIVE_SIGNATURE,
                    sizeof(DAMAGE_EFFECTIVE_SIGNATURE),
                    &damage_effective_trampoline);
    rollback_detour(CONTACT_SITE, CONTACT_SIGNATURE,
                    sizeof(CONTACT_SIGNATURE), &contact_trampoline);
    rollback_detour(FUEL_POST_CONSUME, FUEL_POST_CONSUME_SIGNATURE,
                    sizeof(FUEL_POST_CONSUME_SIGNATURE),
                    &fuel_post_consume_trampoline);
    rollback_detour(FUEL_DEPLETION, FUEL_DEPLETION_SIGNATURE,
                    sizeof(FUEL_DEPLETION_SIGNATURE),
                    &fuel_depletion_trampoline);
    rollback_detour(RENDER_FINAL, RENDER_FINAL_SIGNATURE,
                    sizeof(RENDER_FINAL_SIGNATURE), &render_final_trampoline);
    rollback_detour(CAMERA_COMMIT, CAMERA_COMMIT_SIGNATURE,
                    sizeof(CAMERA_COMMIT_SIGNATURE), &camera_commit_trampoline);
    rollback_detour(COLLISION_COMMIT, COLLISION_COMMIT_SIGNATURE,
                    sizeof(COLLISION_COMMIT_SIGNATURE),
                    &collision_commit_trampoline);
    rollback_detour(COLLISION_ENTRY, COLLISION_SIGNATURE,
                    sizeof(COLLISION_SIGNATURE), &collision_entry_trampoline);
    rollback_detour(FLIGHT_STEP_LEAVE, LEAVE_SIGNATURE,
                    sizeof(LEAVE_SIGNATURE), &flight_leave_trampoline);
    rollback_detour(FLIGHT_STEP_ENTRY, ENTRY_SIGNATURE,
                    sizeof(ENTRY_SIGNATURE), &flight_entry_trampoline);
    rollback_detour(CONTROLS_POST, CONTROLS_POST_SIGNATURE,
                    sizeof(CONTROLS_POST_SIGNATURE), &controls_post_trampoline);
    rollback_detour(CONTROLS_PRE, CONTROLS_PRE_SIGNATURE,
                    sizeof(CONTROLS_PRE_SIGNATURE), &controls_pre_trampoline);
    rollback_detour(shadow_rotation_setter_target,
                    SHADOW_ROTATION_SETTER_SIGNATURE,
                    sizeof(SHADOW_ROTATION_SETTER_SIGNATURE),
                    &shadow_rotation_setter_trampoline);
    rollback_detour(shadow_world_relation_target,
                    SHADOW_WORLD_RELATION_SIGNATURE,
                    sizeof(SHADOW_WORLD_RELATION_SIGNATURE),
                    &shadow_world_relation_trampoline);
    rollback_detour(shadow_polygon_render_target,
                    SHADOW_POLYGON_RENDER_SIGNATURE,
                    sizeof(SHADOW_POLYGON_RENDER_SIGNATURE),
                    &shadow_polygon_render_trampoline);
    rollback_detour(shadow_visible_polygons_target,
                    SHADOW_VISIBLE_POLYGONS_SIGNATURE,
                    sizeof(SHADOW_VISIBLE_POLYGONS_SIGNATURE),
                    &shadow_visible_polygons_trampoline);
    rollback_detour(shadow_visible_objects_target,
                    SHADOW_VISIBLE_OBJECTS_SIGNATURE,
                    sizeof(SHADOW_VISIBLE_OBJECTS_SIGNATURE),
                    &shadow_visible_objects_trampoline);
    rollback_detour(shadow_render_room_target,
                    SHADOW_RENDER_ROOM_SIGNATURE,
                    sizeof(SHADOW_RENDER_ROOM_SIGNATURE),
                    &shadow_render_room_trampoline);
    rollback_detour(shadow_camera_render_target,
                    SHADOW_CAMERA_RENDER_SIGNATURE,
                    sizeof(SHADOW_CAMERA_RENDER_SIGNATURE),
                    &shadow_camera_render_trampoline);
    rollback_detour(AIRPLANE_PRESENTATION,
                    AIRPLANE_PRESENTATION_SIGNATURE,
                    sizeof(AIRPLANE_PRESENTATION_SIGNATURE),
                    &airplane_presentation_trampoline);
    rollback_detour(RENDER_LIST_DISPATCH,
                    RENDER_LIST_DISPATCH_SIGNATURE,
                    sizeof(RENDER_LIST_DISPATCH_SIGNATURE),
                    &render_list_dispatch_trampoline);
    rollback_detour(PARTICLE_PLACE, PARTICLE_PLACE_SIGNATURE,
                    sizeof(PARTICLE_PLACE_SIGNATURE),
                    &particle_place_trampoline);
    rollback_detour(PARTICLE_RESET, PARTICLE_RESET_SIGNATURE,
                    sizeof(PARTICLE_RESET_SIGNATURE),
                    &particle_reset_trampoline);
    rollback_detour(PARTICLE_EMITTER_TICK,
                    PARTICLE_EMITTER_TICK_SIGNATURE,
                    sizeof(PARTICLE_EMITTER_TICK_SIGNATURE),
                    &particle_emitter_tick_trampoline);
    rollback_detour(POSITION_CHARACTER_WRITE,
                    POSITION_CHARACTER_WRITE_SIGNATURE,
                    sizeof(POSITION_CHARACTER_WRITE_SIGNATURE),
                    &position_character_write_trampoline);
    rollback_detour(UDSP_DISPATCH, UDSP_DISPATCH_SIGNATURE,
                    sizeof(UDSP_DISPATCH_SIGNATURE),
                    &udsp_dispatch_trampoline);
    rollback_detour(EXHIBITION_CALLBACK, EXHIBITION_CALLBACK_SIGNATURE,
                    sizeof(EXHIBITION_CALLBACK_SIGNATURE),
                    &exhibition_callback_trampoline);
    rollback_detour(FLIGHT_TARGET, FLIGHT_TARGET_SIGNATURE,
                    sizeof(FLIGHT_TARGET_SIGNATURE),
                    &flight_target_trampoline);
    rollback_detour(QUEUE_MODE, QUEUE_MODE_SIGNATURE,
                    sizeof(QUEUE_MODE_SIGNATURE), &queue_mode_trampoline);
    rollback_detour(MODE_SET, MODE_SET_SIGNATURE, 8u,
                    &mode_set_trampoline);
    rollback_detour(LOGIN_TICK, LOGIN_TICK_SIGNATURE,
                    sizeof(LOGIN_TICK_SIGNATURE), &login_tick_trampoline);
    rollback_detour(AUDIO_POLL, AUDIO_POLL_SIGNATURE,
                    sizeof(AUDIO_POLL_SIGNATURE), &audio_poll_trampoline);
    rollback_detour(AUDIO_START, AUDIO_START_SIGNATURE,
                    sizeof(AUDIO_START_SIGNATURE), &audio_start_trampoline);
#undef rollback_detour
    if (!rollback_import_hooks()) rollback_ok = FALSE;
    if (!rollback_ok || detour_rollback_failed) {
        session_fail("hook_rollback_failed_module_pinned");
    } else {
        session_fail("hook_installation");
    }
    return 0u;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
    }
    if (reason == DLL_PROCESS_DETACH && trace_file != INVALID_HANDLE_VALUE) {
        /* Other threads are stopped during process teardown; never wait on a
         * critical section that a terminated thread may still own. */
        if (native_dispatch_requested) mvds_disable();
        flush_trace_locked();
        CloseHandle(trace_file);
        trace_file = INVALID_HANDLE_VALUE;
    }
    if (reason == DLL_PROCESS_DETACH) {
        if (replay_focus_stop_event) SetEvent(replay_focus_stop_event);
        if (diagnostic_exception_handler) {
            RemoveVectoredExceptionHandler(diagnostic_exception_handler);
            diagnostic_exception_handler = NULL;
        }
        if (complete_event) CloseHandle(complete_event);
        if (failure_event) CloseHandle(failure_event);
        if (ready_event) CloseHandle(ready_event);
        if (late_bootstrap_event) CloseHandle(late_bootstrap_event);
        if (login_pending_event) CloseHandle(login_pending_event);
        if (login_activation_event) CloseHandle(login_activation_event);
        if (replay_focus_arm_event) CloseHandle(replay_focus_arm_event);
        if (replay_focus_applied_event) {
            CloseHandle(replay_focus_applied_event);
        }
        if (replay_focus_stop_event) CloseHandle(replay_focus_stop_event);
        if (replay_ticks) HeapFree(GetProcessHeap(), 0, replay_ticks);
        if (replay_focus_events) {
            HeapFree(GetProcessHeap(), 0, replay_focus_events);
        }
        if (replay_activation_dts) {
            HeapFree(GetProcessHeap(), 0, replay_activation_dts);
        }
        complete_event = NULL;
        failure_event = NULL;
        ready_event = NULL;
        late_bootstrap_event = NULL;
        login_pending_event = NULL;
        login_activation_event = NULL;
        replay_focus_arm_event = NULL;
        replay_focus_applied_event = NULL;
        replay_focus_stop_event = NULL;
        replay_ticks = NULL;
        replay_focus_events = NULL;
        replay_activation_dts = NULL;
        if (native_dispatch_shared_identity) {
            UnmapViewOfFile(native_dispatch_shared_identity);
            native_dispatch_shared_identity = NULL;
        }
        if (native_dispatch_identity_mapping) {
            CloseHandle(native_dispatch_identity_mapping);
            native_dispatch_identity_mapping = NULL;
        }
    }
    return TRUE;
}
