#ifndef MIEL_VLIEGT_NATIVE_DISPATCH_SEMANTIC_HOOK_H
#define MIEL_VLIEGT_NATIVE_DISPATCH_SEMANTIC_HOOK_H

#include <windows.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MVDS_PROTOCOL "miel-vliegt-native-dispatch-semantic-wire"
#define MVDS_CAPTURE_SESSION_CAP 48
#define MVDS_IDENTITY_MAPPING_PREFIX "Local\\MielNativeDispatchIdentity-"
#define MVDS_EXECUTABLE_SHA256 \
    "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2"
#ifndef MVDS_PRODUCER_BUILD_SHA256
#define MVDS_PRODUCER_BUILD_SHA256 "UNBOUND_COMPILE_ONLY"
#endif

typedef enum MvdsRoute {
    MVDS_ROUTE_NONE = 0,
    MVDS_ROUTE_GROUND = 1,
    MVDS_ROUTE_BARN = 2,
    MVDS_ROUTE_FLIGHT = 3,
    MVDS_ROUTE_LOCATION_POLICY = 4
} MvdsRoute;

typedef enum MvdsEvidenceClass {
    MVDS_EVIDENCE_NONE = 0,
    MVDS_EVIDENCE_MISSION_DISPATCH,
    MVDS_EVIDENCE_LOCATION_POLICY
} MvdsEvidenceClass;

typedef enum MvdsCaptureHookFamily {
    MVDS_CAPTURE_HOOK_NONE = 0,
    MVDS_CAPTURE_HOOK_ACTION_GROUND,
    MVDS_CAPTURE_HOOK_ACTION_BARN,
    MVDS_CAPTURE_HOOK_ACTION_FLIGHT,
    MVDS_CAPTURE_HOOK_ACTION_OUTRO,
    MVDS_CAPTURE_HOOK_GENERIC_LOCATION_ENTER,
    MVDS_CAPTURE_HOOK_GROTTE_STATE_SETTER,
    MVDS_CAPTURE_HOOK_RAYMOND_LOCATION_LOAD,
    MVDS_CAPTURE_HOOK_RAYMOND_STATE_SETTER,
    MVDS_CAPTURE_HOOK_EXHIBITION_STATE_SETTER,
    MVDS_CAPTURE_HOOK_MYGGHANGET_ENTER
} MvdsCaptureHookFamily;

typedef enum MvdsCaptureDriver {
    MVDS_CAPTURE_DRIVER_NONE = 0,
    MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2,
    MVDS_CAPTURE_DRIVER_BOOTSTRAP_TRAVERSAL_V1,
    MVDS_CAPTURE_DRIVER_MISSION_LOCATION_ENTER_V1,
    MVDS_CAPTURE_DRIVER_MISSION_BARN_TRAVERSAL_V1
} MvdsCaptureDriver;

typedef struct MvdsMissionCaptureTarget {
    const char *source_path;
    const char *mission_key;
    DWORD mission_id;
    const char *mission_phase;
    DWORD native_action_ordinal;
    const char *opcode;
    MvdsRoute route;
    MvdsCaptureHookFamily hook_family;
} MvdsMissionCaptureTarget;

typedef struct MvdsLocationCaptureTarget {
    DWORD location_id;
    const char *selector;
    const char *mode;
    MvdsCaptureHookFamily hook_family;
    int event_argument;
} MvdsLocationCaptureTarget;

typedef struct MvdsCaptureTarget {
    MvdsEvidenceClass evidence_class;
    MvdsCaptureDriver capture_driver;
    const char *driver_mode;
    const char *driver_bootstrap_profile_sha256;
    const char *driver_scenario_sha256;
    const char *driver_initial_user_sha256;
    const char *plan_manifest_sha256;
    const char *capture_plan_sha256;
    const char *job_id;
    const char *job_sha256;
    const char *claim_id;
    const char *claim_sha256;
    const char *subject_sha256;
    const char *expectation_sha256;
    const char *scenario_sha256;
    const char *native_slice_sha256;
    const char *target_sha256;
    union {
        MvdsMissionCaptureTarget mission;
        MvdsLocationCaptureTarget location;
    } trigger;
} MvdsCaptureTarget;

typedef struct MvdsFinalMissionReadback {
    int state;
    DWORD mission_address;
    BOOL mission_present;
    DWORD application_getter_address;
    DWORD mission_lookup_address;
    DWORD mission_complete_address;
} MvdsFinalMissionReadback;

typedef struct MvdsSharedProcessIdentity {
    DWORD schema;
    DWORD native_process_id;
    volatile LONG ready;
    volatile LONG capture_complete;
    char capture_session_id[MVDS_CAPTURE_SESSION_CAP];
} MvdsSharedProcessIdentity;

typedef enum MvdsHookId {
    MVDS_HOOK_MISSION_PARSE = 0,
    MVDS_HOOK_MISSION_INSERT,
    MVDS_HOOK_MISSION_EXECUTOR,
    MVDS_HOOK_ACTION_GROUND,
    MVDS_HOOK_ACTION_BARN,
    MVDS_HOOK_ACTION_FLIGHT,
    MVDS_HOOK_ACTION_OUTRO,
    MVDS_HOOK_ACTION_OUTRO_COMMIT,
    MVDS_HOOK_ROOT_FACTORY,
    MVDS_HOOK_GENERIC_ENTER,
    MVDS_HOOK_GENERIC_FINAL_MISSION_PRESENT,
    MVDS_HOOK_GENERIC_FINAL_TRUE,
    MVDS_HOOK_GROTTE_SETTER,
    MVDS_HOOK_GROTTE_REFUEL_BRANCH,
    MVDS_HOOK_RAYMOND_LOAD,
    MVDS_HOOK_RAYMOND_FIRST_BRANCH,
    MVDS_HOOK_RAYMOND_SETTER,
    MVDS_HOOK_RAYMOND_RESULT_BRANCH,
    MVDS_HOOK_EXHIBITION_SETTER,
    MVDS_HOOK_EXHIBITION_PROJECTION,
    MVDS_HOOK_EXHIBITION_LT_900,
    MVDS_HOOK_EXHIBITION_LT_900_SELECTED,
    MVDS_HOOK_EXHIBITION_LT_2200,
    MVDS_HOOK_EXHIBITION_LT_2200_SELECTED,
    MVDS_HOOK_EXHIBITION_LT_2200_FINAL_TRUE,
    MVDS_HOOK_EXHIBITION_GTE_2200,
    MVDS_HOOK_EXHIBITION_GTE_2200_FINAL_TRUE,
    MVDS_HOOK_EXHIBITION_FINAL_FALSE,
    MVDS_HOOK_EXHIBITION_OUTRO,
    MVDS_HOOK_MYGGHANGET_ENTER,
    MVDS_HOOK_COUNT
} MvdsHookId;

typedef enum MvdsRel32Opcode {
    MVDS_REL32_CALL = 0xe8,
    MVDS_REL32_JUMP = 0xe9
} MvdsRel32Opcode;

/* Every relative CALL/JMP whose five bytes are copied into a trampoline must
 * be declared explicitly.  opcode_offset addresses the opcode byte, not its
 * displacement.  The observer validates this metadata against the pinned
 * signature before it allocates or publishes executable code. */
typedef struct MvdsRel32Relocation {
    size_t opcode_offset;
    MvdsRel32Opcode opcode;
} MvdsRel32Relocation;

typedef struct MvdsHookSpec {
    MvdsHookId id;
    const char *name;
    BYTE *target;
    const BYTE *signature;
    size_t signature_size;
    size_t minimum_patch_size;
    void *hook;
    void **trampoline_slot;
    BOOL inline_site;
    const MvdsRel32Relocation *rel32_relocations;
    size_t rel32_relocation_count;
} MvdsHookSpec;

/* Returning FALSE means the record was not durably accepted.  The producer
 * treats that as a fatal capture failure; a merely attempted write is never
 * evidence. */
typedef BOOL (*MvdsEmitLine)(const char *line, DWORD size, void *context);
typedef void (*MvdsFailure)(const char *reason, void *context);
typedef BOOL (*MvdsCaptureCompleted)(DWORD native_process_id,
    const char *capture_session_id, void *context);

typedef struct MvdsHost {
    MvdsEmitLine emit_line;
    MvdsFailure fail_closed;
    MvdsCaptureCompleted capture_completed;
    void *context;
    DWORD engine_thread_id;
    const char *capture_plan_job_id;
    const char *native_slice_sha256;
    const char *observer_binary_sha256;
    const char *observer_build_receipt_sha256;
} MvdsHost;

/* The host owns detour installation and rollback.  It preflights every spec,
 * installs exactly the target-derived required subset, and then calls
 * mvds_arm exactly once.  mvds_arm rejects both missing required detours and
 * extra detours outside that subset. */
const MvdsHookSpec *mvds_hook_specs(size_t *count);
BOOL mvds_hook_required(MvdsHookId id);
DWORD mvds_required_hook_mask(void);
/* Arm immediately after installing detours, before the engine is resumed.
 * Source/root pointer maps are collected, but no supported capability or
 * semantic event is emitted until the engine thread is bound and the exact
 * configured native target hook opens the one-shot capture window. */
BOOL mvds_arm(const MvdsHost *host, BOOL existing_route_hooks_forward_events);
BOOL mvds_configure_capture_target(const MvdsCaptureTarget *target);
DWORD mvds_native_process_id(void);
const char *mvds_capture_session_id(void);
BOOL mvds_bind_engine_thread(DWORD engine_thread_id);
/* Read-only call-through to the original executable's mission lookup and
 * completion functions.  This never synthesizes, projects, or writes state. */
BOOL mvds_read_final_mission_state(MvdsFinalMissionReadback *readback);
BOOL mvds_completed_generic_readback(MvdsFinalMissionReadback *readback);
BOOL mvds_mygghanget_absence_completed(void);
BOOL mvds_capture_event_completed(void);
/* A process may open exactly one claim-bound capture window. This entry point
 * rejects host/manager/timer callers; only a matching producer hook receives
 * the private authorization needed to call it immediately before native code.
 * The producer closes after exactly one semantic EVENT. Log slicing is
 * forbidden. */
BOOL mvds_begin_capture_window(void);
BOOL mvds_end_capture_window(void);
BOOL mvds_enable(const MvdsHost *host, BOOL existing_route_hooks_forward_events);
void mvds_disable(void);

/* Existing observer route hooks call this at dispatch entry.  The producer
 * only accepts it on the pinned engine thread while an exact semantic frame is
 * active. */
void mvds_observe_route(MvdsRoute route, DWORD object, DWORD root);

#ifdef __cplusplus
}
#endif

#endif
