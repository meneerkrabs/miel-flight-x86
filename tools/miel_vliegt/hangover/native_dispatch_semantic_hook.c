#include "native_dispatch_semantic_hook.h"

#include <ctype.h>
#include <float.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__GNUC__) || !defined(__i386__)
#error "native_dispatch_semantic_hook.c requires 32-bit MinGW GCC"
#endif

#define MVDS_FASTCALL __attribute__((fastcall))
#define THISCALL __attribute__((thiscall))
#define NAKED __attribute__((naked))
#define ASM_USED __attribute__((used))
#define ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))
#define MVDS_PREFIX "MVDS "
#define PATH_CAP 260
#define ARTIFACT_CAP 160
#define MISSION_CAP 256
#define ROOT_CAP 1024
#define CAPTURE_JOB_CAP 128

typedef void *(THISCALL *ParseFn)(void *, DWORD, const char *);
typedef void (THISCALL *InsertFn)(void *, void *);
typedef void (THISCALL *ExecutorFn)(void *, DWORD);
typedef void *(__cdecl *RootFactoryFn)(void *, const char *);
typedef void (THISCALL *VoidThisFn)(void *);
typedef BYTE (THISCALL *RaymondLoadFn)(void *, DWORD);
typedef void (THISCALL *SetterFn)(void *, int);

typedef struct MissionBinding {
    DWORD mission;
    char path[PATH_CAP];
} MissionBinding;

typedef struct RootBinding {
    DWORD root;
    char artifact[ARTIFACT_CAP];
} RootBinding;

typedef struct MissionSourceSlot {
    volatile LONG owner_thread_id;
    BOOL active;
    DWORD depth;
    DWORD container;
    DWORD insert_count;
    char path[PATH_CAP];
} MissionSourceSlot;

typedef struct ActionFrame {
    BOOL active;
    DWORD mission;
    DWORD node;
    MvdsRoute expected_route;
    MvdsRoute observed_route;
    DWORD observed_root;
    DWORD expected_object;
    DWORD executor_phase;
    BOOL outro_commit_observed;
    DWORD outro_object;
} ActionFrame;

typedef enum SelectorKind {
    SELECTOR_NONE = 0,
    SELECTOR_GENERIC,
    SELECTOR_GROTTE,
    SELECTOR_RAYMOND_ENTRY,
    SELECTOR_RAYMOND_RESULT,
    SELECTOR_EXHIBITION,
    SELECTOR_MYGGHANGET
} SelectorKind;

typedef struct SelectorFrame {
    SelectorKind kind;
    DWORD object;
    MvdsRoute observed_route;
    DWORD observed_root;
    BOOL root_without_provenance;
    BOOL mygghanget_root_created;
    BOOL projected_x_observed;
    float projected_x;
    BOOL projection_site_observed;
    BOOL predicate_site_observed;
    BOOL secondary_predicate_site_observed;
    BOOL final_mission_present;
    BOOL final_predicate_observed;
    BOOL final_mission_complete;
    int terminal_branch;
    int observed_predicate_value;
    int observed_result;
} SelectorFrame;

typedef struct ExhibitionEntryInterval {
    BOOL active;
    DWORD object;
    DWORD thread_id;
} ExhibitionEntryInterval;

static MvdsHost g_host;
static BOOL g_armed;
static BOOL g_enabled;
static BOOL g_fatal;
static BOOL g_capture_window_active;
static BOOL g_capture_window_consumed;
static BOOL g_capture_event_emitted;
static BOOL g_capture_completion_signalled;
static BOOL g_target_hook_open_authorized;
static BOOL g_capture_target_configured;
static MvdsCaptureTarget g_capture_target;
static BOOL g_route_forwarding;
static MvdsFinalMissionReadback g_completed_generic_readback;
static BOOL g_completed_generic_readback_valid;
static DWORD g_native_process_id;
static char g_capture_session_id[MVDS_CAPTURE_SESSION_CAP];
static CRITICAL_SECTION g_lock;
static BOOL g_lock_initialized;
static LONG g_sequence;
static MissionSourceSlot g_mission_sources[8];
static MissionBinding g_missions[MISSION_CAP];
static size_t g_mission_count;
static RootBinding g_roots[ROOT_CAP];
static size_t g_root_count;
static ActionFrame g_action;
static SelectorFrame g_selector;
static ExhibitionEntryInterval g_exhibition_entry;
static char g_capture_plan_job_id[CAPTURE_JOB_CAP];
static char g_native_slice_sha256[65];
static char g_observer_binary_sha256[65];
static char g_observer_build_receipt_sha256[65];

static ParseFn g_parse_trampoline;
static InsertFn g_insert_trampoline;
static ExecutorFn g_executor_trampoline;
static void *g_action_ground_trampoline;
static void *g_action_barn_trampoline;
static void *g_action_flight_trampoline;
static void *g_action_outro_trampoline;
static void *g_action_outro_commit_trampoline;
static RootFactoryFn g_root_factory_trampoline;
static VoidThisFn g_generic_enter_trampoline;
static void *g_generic_final_mission_present_trampoline;
static void *g_generic_final_true_trampoline;
static SetterFn g_grotte_setter_trampoline;
static void *g_grotte_refuel_branch_trampoline;
static RaymondLoadFn g_raymond_load_trampoline;
static void *g_raymond_first_branch_trampoline;
static SetterFn g_raymond_setter_trampoline;
static void *g_raymond_result_branch_trampoline;
static SetterFn g_exhibition_setter_trampoline;
static void *g_exhibition_projection_trampoline;
static void *g_exhibition_projected_x_trampoline;
static void *g_exhibition_lt_900_selected_trampoline;
static void *g_exhibition_lt_2200_trampoline;
static void *g_exhibition_lt_2200_selected_trampoline;
static void *g_exhibition_lt_2200_final_true_trampoline;
static void *g_exhibition_gte_2200_trampoline;
static void *g_exhibition_gte_2200_final_true_trampoline;
static void *g_exhibition_final_false_trampoline;
static void *g_exhibition_outro_trampoline;
static VoidThisFn g_mygghanget_enter_trampoline;

static const BYTE SIG_PARSE[] = {0x64,0xa1,0x00,0x00,0x00,0x00,0x6a,0xff};
static const BYTE SIG_INSERT[] = {0x8b,0x44,0x24,0x04,0x89};
static const BYTE SIG_EXECUTOR[] = {0x6a,0xff,0x68,0x88,0xa7,0x44,0x00};
static const BYTE SIG_ACTION_GROUND[] = {0x8b,0x43,0x08,0x85,0xc0};
static const BYTE SIG_ACTION_BARN[] = {0x8b,0x43,0x08,0x85,0xc0};
static const BYTE SIG_ACTION_FLIGHT[] = {0x8b,0x43,0x08,0x85,0xc0};
static const BYTE SIG_ACTION_OUTRO[] = {0xe8,0xc0,0xf2,0xfc,0xff};
static const BYTE SIG_ACTION_OUTRO_COMMIT[] = {0xc6,0x80,0xac,0x48,0x00,0x00,0x01};
static const BYTE SIG_ROOT_FACTORY[] = {0x6a,0xff,0x68,0x72,0xaa,0x44,0x00};
static const BYTE SIG_GENERIC_ENTER[] = {0x83,0xec,0x48,0x53,0x56};
static const BYTE SIG_GENERIC_FINAL_PRESENT[] = {0x8b,0xc8,0xe8,0xc1,0x0b,0x01,0x00};
static const BYTE SIG_GENERIC_FINAL_TRUE[] = {0x8b,0x96,0xcc,0x08,0x00,0x00};
static const BYTE SIG_GROTTE_SETTER[] = {0x56,0x8b,0xf1,0x8b,0x4c,0x24,0x08};
static const BYTE SIG_GROTTE_BRANCH[] = {0x8a,0x86,0xa4,0x48,0x00,0x00};
static const BYTE SIG_RAYMOND_LOAD[] = {0x64,0xa1,0x00,0x00,0x00,0x00,0x6a,0xff};
static const BYTE SIG_RAYMOND_FIRST[] = {0x8a,0x86,0x9c,0x48,0x00,0x00};
static const BYTE SIG_RAYMOND_SETTER[] = {0x8b,0x44,0x24,0x04,0x83,0xec,0x44};
static const BYTE SIG_RAYMOND_RESULT[] = {0x8a,0x86,0x94,0x48,0x00,0x00};
static const BYTE SIG_EXHIBITION_SETTER[] = {0x83,0xec,0x18,0x53,0x56,0x57};
static const BYTE SIG_EXHIBITION_PROJECTION[] = {0x8b,0x4e,0x5c,0x8d,0x54,0x24,0x18};
static const BYTE SIG_EXHIBITION_X[] = {0xd9,0x44,0x24,0x0c,0xd8,0x1d,0x84,0xd9,0x44,0x00};
static const BYTE SIG_EXHIBITION_LT_900_SELECTED[] = {0x8b,0x8e,0x94,0x48,0x00,0x00};
static const BYTE SIG_EXHIBITION_LT_2200[] = {0xd9,0x44,0x24,0x0c,0xd8,0x1d,0x80,0xd9,0x44,0x00};
static const BYTE SIG_EXHIBITION_LT_2200_SELECTED[] = {0x8b,0x8e,0xb4,0x48,0x00,0x00};
static const BYTE SIG_EXHIBITION_LT_2200_FINAL_TRUE[] = {0x8b,0x96,0xa0,0x48,0x00,0x00};
static const BYTE SIG_EXHIBITION_GTE_2200[] = {0x8b,0x8e,0xbc,0x48,0x00,0x00};
static const BYTE SIG_EXHIBITION_GTE_2200_FINAL_TRUE[] = {0x8b,0x96,0xa4,0x48,0x00,0x00};
static const BYTE SIG_EXHIBITION_FINAL_FALSE[] = {0x57,0x8b,0xce,0xe8,0xf3,0x24,0xfe,0xff};
static const BYTE SIG_EXHIBITION_OUTRO[] = {0x8b,0x8e,0xc0,0x48,0x00,0x00};
static const BYTE SIG_MYGGHANGET[] = {0x56,0x8b,0xf1,0xc6,0x86,0x91,0x48,0x00,0x00,0x01};

static const MvdsRel32Relocation REL32_ACTION_OUTRO[] = {
    {0u, MVDS_REL32_CALL}
};
static const MvdsRel32Relocation REL32_GENERIC_FINAL_PRESENT[] = {
    {2u, MVDS_REL32_CALL}
};
static const MvdsRel32Relocation REL32_EXHIBITION_FINAL_FALSE[] = {
    {3u, MVDS_REL32_CALL}
};

static void *MVDS_FASTCALL hook_parse(void *self, DWORD ignored, DWORD arg, const char *path);
static void MVDS_FASTCALL hook_insert(void *self, DWORD ignored, void *mission);
static void MVDS_FASTCALL hook_executor(void *self, DWORD ignored, DWORD phase);
static void NAKED hook_action_ground(void);
static void NAKED hook_action_barn(void);
static void NAKED hook_action_flight(void);
static void NAKED hook_action_outro(void);
static void NAKED hook_action_outro_commit(void);
static void *__cdecl hook_root_factory(void *owner, const char *path);
static void MVDS_FASTCALL hook_generic_enter(void *self, DWORD ignored);
static void NAKED hook_generic_final_mission_present(void);
static void NAKED hook_generic_final_true(void);
static void MVDS_FASTCALL hook_grotte_setter(void *self, DWORD ignored, int event);
static void NAKED hook_grotte_refuel_branch(void);
static BYTE MVDS_FASTCALL hook_raymond_load(void *self, DWORD ignored, DWORD argument);
static void NAKED hook_raymond_first_branch(void);
static void MVDS_FASTCALL hook_raymond_setter(void *self, DWORD ignored, int event);
static void NAKED hook_raymond_result_branch(void);
static void MVDS_FASTCALL hook_exhibition_setter(void *self, DWORD ignored, int event);
static void NAKED hook_exhibition_projection(void);
static void NAKED hook_exhibition_projected_x(void);
static void NAKED hook_exhibition_lt_900_selected(void);
static void NAKED hook_exhibition_lt_2200(void);
static void NAKED hook_exhibition_lt_2200_selected(void);
static void NAKED hook_exhibition_lt_2200_final_true(void);
static void NAKED hook_exhibition_gte_2200(void);
static void NAKED hook_exhibition_gte_2200_final_true(void);
static void NAKED hook_exhibition_final_false(void);
static void NAKED hook_exhibition_outro(void);
static void MVDS_FASTCALL hook_mygghanget_enter(void *self, DWORD ignored);
static void begin_selector(SelectorKind kind, void *self);
static void end_selector(void);
static void fail_closed(const char *reason);
static BOOL begin_capture_window_from_target_hook(MvdsCaptureHookFamily family);

#define MVDS_SPEC(id,name,target,signature,patch,hook,slot,inline_site) \
    {id,name,target,signature,sizeof(signature),patch,hook,slot,inline_site,NULL,0u}
#define MVDS_REL32_SPEC(id,name,target,signature,patch,hook,slot,inline_site,relocations) \
    {id,name,target,signature,sizeof(signature),patch,hook,slot,inline_site, \
        relocations,ARRAY_COUNT(relocations)}

static const MvdsHookSpec g_specs[] = {
    MVDS_SPEC(MVDS_HOOK_MISSION_PARSE,"MISSION_FILE_PARSE",(BYTE *)0x00437670,SIG_PARSE,8,hook_parse,(void **)&g_parse_trampoline,FALSE),
    MVDS_SPEC(MVDS_HOOK_MISSION_INSERT,"MISSION_INSERT",(BYTE *)0x00437610,SIG_INSERT,5,hook_insert,(void **)&g_insert_trampoline,FALSE),
    MVDS_SPEC(MVDS_HOOK_MISSION_EXECUTOR,"MISSION_ACTION_EXECUTE",(BYTE *)0x00436270,SIG_EXECUTOR,7,hook_executor,(void **)&g_executor_trampoline,FALSE),
    MVDS_SPEC(MVDS_HOOK_ACTION_GROUND,"ACTION_GROUND",(BYTE *)0x004362f1,SIG_ACTION_GROUND,5,hook_action_ground,&g_action_ground_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_ACTION_BARN,"ACTION_BARN",(BYTE *)0x004364c9,SIG_ACTION_BARN,5,hook_action_barn,&g_action_barn_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_ACTION_FLIGHT,"ACTION_FLIGHT",(BYTE *)0x00436497,SIG_ACTION_FLIGHT,5,hook_action_flight,&g_action_flight_trampoline,TRUE),
    MVDS_REL32_SPEC(MVDS_HOOK_ACTION_OUTRO,"ACTION_OUTRO",(BYTE *)0x0043675b,SIG_ACTION_OUTRO,5,hook_action_outro,&g_action_outro_trampoline,TRUE,REL32_ACTION_OUTRO),
    MVDS_SPEC(MVDS_HOOK_ACTION_OUTRO_COMMIT,"ACTION_OUTRO_COMMIT",(BYTE *)0x00436789,SIG_ACTION_OUTRO_COMMIT,7,hook_action_outro_commit,&g_action_outro_commit_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_ROOT_FACTORY,"UDSP_ROOT_FACTORY",(BYTE *)0x0043cd70,SIG_ROOT_FACTORY,7,hook_root_factory,(void **)&g_root_factory_trampoline,FALSE),
    MVDS_SPEC(MVDS_HOOK_GENERIC_ENTER,"GENERIC_LOCATION_ENTER",(BYTE *)0x00425170,SIG_GENERIC_ENTER,5,hook_generic_enter,(void **)&g_generic_enter_trampoline,FALSE),
    MVDS_REL32_SPEC(MVDS_HOOK_GENERIC_FINAL_MISSION_PRESENT,"GENERIC_FINAL_MISSION_PRESENT",(BYTE *)0x004254c8,SIG_GENERIC_FINAL_PRESENT,7,hook_generic_final_mission_present,&g_generic_final_mission_present_trampoline,TRUE,REL32_GENERIC_FINAL_PRESENT),
    MVDS_SPEC(MVDS_HOOK_GENERIC_FINAL_TRUE,"GENERIC_FINAL_TRUE",(BYTE *)0x004254d3,SIG_GENERIC_FINAL_TRUE,6,hook_generic_final_true,&g_generic_final_true_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_GROTTE_SETTER,"GROTTE_STATE_SETTER",(BYTE *)0x00441830,SIG_GROTTE_SETTER,7,hook_grotte_setter,(void **)&g_grotte_setter_trampoline,FALSE),
    MVDS_SPEC(MVDS_HOOK_GROTTE_REFUEL_BRANCH,"GROTTE_REFUEL_BRANCH",(BYTE *)0x00441865,SIG_GROTTE_BRANCH,6,hook_grotte_refuel_branch,&g_grotte_refuel_branch_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_RAYMOND_LOAD,"RAYMOND_LOCATION_LOAD",(BYTE *)0x00441d00,SIG_RAYMOND_LOAD,8,hook_raymond_load,(void **)&g_raymond_load_trampoline,FALSE),
    MVDS_SPEC(MVDS_HOOK_RAYMOND_FIRST_BRANCH,"RAYMOND_FIRST_BRANCH",(BYTE *)0x00441e99,SIG_RAYMOND_FIRST,6,hook_raymond_first_branch,&g_raymond_first_branch_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_RAYMOND_SETTER,"RAYMOND_STATE_SETTER",(BYTE *)0x00441fe0,SIG_RAYMOND_SETTER,7,hook_raymond_setter,(void **)&g_raymond_setter_trampoline,FALSE),
    MVDS_SPEC(MVDS_HOOK_RAYMOND_RESULT_BRANCH,"RAYMOND_RESULT_BRANCH",(BYTE *)0x0044202f,SIG_RAYMOND_RESULT,6,hook_raymond_result_branch,&g_raymond_result_branch_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_EXHIBITION_SETTER,"EXHIBITION_STATE_SETTER",(BYTE *)0x00443d50,SIG_EXHIBITION_SETTER,6,hook_exhibition_setter,(void **)&g_exhibition_setter_trampoline,FALSE),
    MVDS_SPEC(MVDS_HOOK_EXHIBITION_PROJECTION,"EXHIBITION_PROJECTION",(BYTE *)0x00443d7e,SIG_EXHIBITION_PROJECTION,7,hook_exhibition_projection,&g_exhibition_projection_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_EXHIBITION_LT_900,"EXHIBITION_LT_900",(BYTE *)0x00443db4,SIG_EXHIBITION_X,10,hook_exhibition_projected_x,&g_exhibition_projected_x_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_EXHIBITION_LT_900_SELECTED,"EXHIBITION_LT_900_SELECTED",(BYTE *)0x00443dcb,SIG_EXHIBITION_LT_900_SELECTED,6,hook_exhibition_lt_900_selected,&g_exhibition_lt_900_selected_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_EXHIBITION_LT_2200,"EXHIBITION_LT_2200",(BYTE *)0x00443e45,SIG_EXHIBITION_LT_2200,10,hook_exhibition_lt_2200,&g_exhibition_lt_2200_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_EXHIBITION_LT_2200_SELECTED,"EXHIBITION_LT_2200_SELECTED",(BYTE *)0x00443e5a,SIG_EXHIBITION_LT_2200_SELECTED,6,hook_exhibition_lt_2200_selected,&g_exhibition_lt_2200_selected_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_EXHIBITION_LT_2200_FINAL_TRUE,"EXHIBITION_LT_2200_FINAL_TRUE",(BYTE *)0x00443eef,SIG_EXHIBITION_LT_2200_FINAL_TRUE,6,hook_exhibition_lt_2200_final_true,&g_exhibition_lt_2200_final_true_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_EXHIBITION_GTE_2200,"EXHIBITION_GTE_2200",(BYTE *)0x00443f0c,SIG_EXHIBITION_GTE_2200,6,hook_exhibition_gte_2200,&g_exhibition_gte_2200_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_EXHIBITION_GTE_2200_FINAL_TRUE,"EXHIBITION_GTE_2200_FINAL_TRUE",(BYTE *)0x00443f9f,SIG_EXHIBITION_GTE_2200_FINAL_TRUE,6,hook_exhibition_gte_2200_final_true,&g_exhibition_gte_2200_final_true_trampoline,TRUE),
    MVDS_REL32_SPEC(MVDS_HOOK_EXHIBITION_FINAL_FALSE,"EXHIBITION_FINAL_FALSE",(BYTE *)0x00444075,SIG_EXHIBITION_FINAL_FALSE,8,hook_exhibition_final_false,&g_exhibition_final_false_trampoline,TRUE,REL32_EXHIBITION_FINAL_FALSE),
    MVDS_SPEC(MVDS_HOOK_EXHIBITION_OUTRO,"EXHIBITION_OUTRO",(BYTE *)0x00443fbc,SIG_EXHIBITION_OUTRO,6,hook_exhibition_outro,&g_exhibition_outro_trampoline,TRUE),
    MVDS_SPEC(MVDS_HOOK_MYGGHANGET_ENTER,"MYGGHANGET_ENTER",(BYTE *)0x00441a60,SIG_MYGGHANGET,10,hook_mygghanget_enter,(void **)&g_mygghanget_enter_trampoline,FALSE)
};

_Static_assert(ARRAY_COUNT(g_specs) == MVDS_HOOK_COUNT,
    "MvdsHookId and g_specs must stay one-to-one");
_Static_assert(MVDS_HOOK_COUNT <= 32,
    "target hook mask must fit in one DWORD");

static BOOL engine_observation_ready(void) {
    return g_armed && g_enabled && !g_fatal &&
        GetCurrentThreadId() == g_host.engine_thread_id;
}

static BOOL on_engine_thread(void) {
    return engine_observation_ready() && g_capture_window_active;
}

static void capture_event_complete(void) {
#ifdef MVDS_TEST_MULTI_EMIT
    g_capture_event_emitted = TRUE;
    return;
#else
    if (g_capture_event_emitted) {
        fail_closed("capture job emitted more than one semantic EVENT");
        return;
    }
    g_capture_event_emitted = TRUE;
    g_capture_window_active = FALSE;
#endif
}

static BOOL mission_source_tracking_required(void) {
    return g_armed && !g_fatal && g_capture_target_configured &&
        g_capture_target.evidence_class == MVDS_EVIDENCE_MISSION_DISPATCH;
}

#define MVDS_HOOK_BIT(id) (1u << (DWORD)(id))

static DWORD capture_target_hook_mask(const MvdsCaptureTarget *target) {
    DWORD mask = MVDS_HOOK_BIT(MVDS_HOOK_ROOT_FACTORY);
    if (target == NULL) return 0u;
    if (target->evidence_class == MVDS_EVIDENCE_MISSION_DISPATCH) {
        mask |= MVDS_HOOK_BIT(MVDS_HOOK_MISSION_PARSE) |
            MVDS_HOOK_BIT(MVDS_HOOK_MISSION_INSERT) |
            MVDS_HOOK_BIT(MVDS_HOOK_MISSION_EXECUTOR);
        switch (target->trigger.mission.hook_family) {
            case MVDS_CAPTURE_HOOK_ACTION_GROUND:
                return mask | MVDS_HOOK_BIT(MVDS_HOOK_ACTION_GROUND);
            case MVDS_CAPTURE_HOOK_ACTION_BARN:
                return mask | MVDS_HOOK_BIT(MVDS_HOOK_ACTION_BARN);
            case MVDS_CAPTURE_HOOK_ACTION_FLIGHT:
                return mask | MVDS_HOOK_BIT(MVDS_HOOK_ACTION_FLIGHT);
            case MVDS_CAPTURE_HOOK_ACTION_OUTRO:
                return mask | MVDS_HOOK_BIT(MVDS_HOOK_ACTION_OUTRO) |
                    MVDS_HOOK_BIT(MVDS_HOOK_ACTION_OUTRO_COMMIT);
            default:
                return 0u;
        }
    }
    if (target->evidence_class != MVDS_EVIDENCE_LOCATION_POLICY) return 0u;
    switch (target->trigger.location.hook_family) {
        case MVDS_CAPTURE_HOOK_GENERIC_LOCATION_ENTER:
            return mask | MVDS_HOOK_BIT(MVDS_HOOK_GENERIC_ENTER) |
                MVDS_HOOK_BIT(MVDS_HOOK_GENERIC_FINAL_MISSION_PRESENT) |
                MVDS_HOOK_BIT(MVDS_HOOK_GENERIC_FINAL_TRUE);
        case MVDS_CAPTURE_HOOK_GROTTE_STATE_SETTER:
            return mask | MVDS_HOOK_BIT(MVDS_HOOK_GROTTE_SETTER) |
                MVDS_HOOK_BIT(MVDS_HOOK_GROTTE_REFUEL_BRANCH);
        case MVDS_CAPTURE_HOOK_RAYMOND_LOCATION_LOAD:
            return mask | MVDS_HOOK_BIT(MVDS_HOOK_RAYMOND_LOAD) |
                MVDS_HOOK_BIT(MVDS_HOOK_RAYMOND_FIRST_BRANCH);
        case MVDS_CAPTURE_HOOK_RAYMOND_STATE_SETTER:
            return mask | MVDS_HOOK_BIT(MVDS_HOOK_RAYMOND_SETTER) |
                MVDS_HOOK_BIT(MVDS_HOOK_RAYMOND_RESULT_BRANCH);
        case MVDS_CAPTURE_HOOK_EXHIBITION_STATE_SETTER:
            mask |= MVDS_HOOK_BIT(MVDS_HOOK_GENERIC_ENTER) |
                MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_SETTER) |
                MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_PROJECTION) |
                MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_LT_900);
            if (strcmp(target->trigger.location.selector,
                    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_LT_900") == 0) {
                return mask |
                    MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_LT_900_SELECTED);
            }
            if (strcmp(target->trigger.location.selector,
                    "LOCATION_ENTER_OUTRO_REQUESTED") == 0) {
                return (mask & ~MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_LT_900)) |
                    MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_OUTRO);
            }
            mask |= MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_LT_2200) |
                MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_FINAL_FALSE);
            if (strstr(target->trigger.location.selector,
                    "900_LTE_PROJECTED_X_LT_2200") != NULL) {
                return mask |
                    MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_LT_2200_SELECTED) |
                    MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_LT_2200_FINAL_TRUE);
            }
            if (strstr(target->trigger.location.selector,
                    "PROJECTED_X_GTE_2200") != NULL) {
                return mask |
                    MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_GTE_2200) |
                    MVDS_HOOK_BIT(MVDS_HOOK_EXHIBITION_GTE_2200_FINAL_TRUE);
            }
            return 0u;
        case MVDS_CAPTURE_HOOK_MYGGHANGET_ENTER:
            return mask | MVDS_HOOK_BIT(MVDS_HOOK_MYGGHANGET_ENTER);
        default:
            return 0u;
    }
}

BOOL mvds_hook_required(MvdsHookId id) {
    if (!g_capture_target_configured || id < 0 || id >= MVDS_HOOK_COUNT) {
        return FALSE;
    }
    return (capture_target_hook_mask(&g_capture_target) &
        MVDS_HOOK_BIT(id)) != 0u;
}

DWORD mvds_required_hook_mask(void) {
    return g_capture_target_configured ?
        capture_target_hook_mask(&g_capture_target) : 0u;
}

static MissionSourceSlot *mission_source_slot(BOOL create) {
    LONG thread = (LONG)GetCurrentThreadId();
    size_t index;
    for (index = 0; index < ARRAY_COUNT(g_mission_sources); index++) {
        if (g_mission_sources[index].owner_thread_id == thread) return &g_mission_sources[index];
    }
    if (!create) return NULL;
    for (index = 0; index < ARRAY_COUNT(g_mission_sources); index++) {
        if (InterlockedCompareExchange(&g_mission_sources[index].owner_thread_id, thread, 0) == 0)
            return &g_mission_sources[index];
    }
    fail_closed("mission source thread map exhausted");
    return NULL;
}

static BOOL read_bytes(DWORD address, void *output, size_t size) {
    SIZE_T read = 0;
    return address != 0 && ReadProcessMemory(GetCurrentProcess(), (const void *)(uintptr_t)address,
        output, size, &read) && read == size;
}

static DWORD read_u32(DWORD address) {
    DWORD value = 0;
    if (!read_bytes(address, &value, sizeof(value)))
        fail_closed("unreadable DWORD in semantic evidence object");
    return value;
}

static BYTE read_u8(DWORD address) {
    BYTE value = 0;
    if (!read_bytes(address, &value, sizeof(value)))
        fail_closed("unreadable BYTE in semantic evidence object");
    return value;
}

static void fail_closed(const char *reason) {
    if (g_fatal) return;
    g_fatal = TRUE;
    if (g_host.fail_closed != NULL) g_host.fail_closed(reason, g_host.context);
}

static BOOL emitf(const char *format, ...) {
    char payload[8192];
    char line[8200];
    int payload_size;
    va_list args;
    if (!on_engine_thread() || g_host.emit_line == NULL) return FALSE;
    va_start(args, format);
    payload_size = vsnprintf(payload, sizeof(payload), format, args);
    va_end(args);
    if (payload_size < 0 || (size_t)payload_size >= sizeof(payload)) {
        fail_closed("semantic wire record overflow");
        return FALSE;
    }
    memcpy(line, MVDS_PREFIX, sizeof(MVDS_PREFIX) - 1);
    memcpy(line + sizeof(MVDS_PREFIX) - 1, payload, (size_t)payload_size);
    line[sizeof(MVDS_PREFIX) - 1 + (size_t)payload_size] = '\n';
    if (!g_host.emit_line(line,
        (DWORD)(sizeof(MVDS_PREFIX) + (size_t)payload_size), g_host.context)) {
        fail_closed("semantic wire record was not durably accepted by host");
        return FALSE;
    }
    return TRUE;
}

static BOOL normalize_path(const char *input, char *output, size_t capacity) {
    size_t length = 0;
    if (input == NULL || capacity == 0) return FALSE;
    while (*input != '\0' && length + 1 < capacity) {
        unsigned char value = (unsigned char)*input++;
        if (value >= 'A' && value <= 'Z') value = (unsigned char)(value + ('a' - 'A'));
        output[length++] = (char)(value == '\\' ? '/' : value);
    }
    output[length] = '\0';
    return *input == '\0';
}

static BOOL copy_remote_string(const char *input, char *output, size_t capacity) {
    size_t index;
    if (input == NULL || capacity < 2) return FALSE;
    for (index = 0; index + 1 < capacity; index++) {
        char value;
        if (!read_bytes((DWORD)(uintptr_t)(input + index), &value, 1)) return FALSE;
        output[index] = value;
        if (value == '\0') return TRUE;
    }
    output[capacity - 1] = '\0';
    return FALSE;
}

static BOOL artifact_from_path(const char *path, char *artifact, size_t capacity) {
    char normalized[PATH_CAP];
    const char *prefix = "data/scripts/locations/";
    const char *value;
    size_t length;
    if (!normalize_path(path, normalized, sizeof(normalized))) return FALSE;
    value = strstr(normalized, prefix);
    if (value == NULL) return FALSE;
    value += strlen(prefix);
    length = strlen(value);
    if (length <= 4 || strcmp(value + length - 4, ".def") != 0) return FALSE;
    length -= 4;
    if (strlen("LOCATION_SCRIPT:") + length + 1 > capacity) return FALSE;
    strcpy(artifact, "LOCATION_SCRIPT:");
    memcpy(artifact + strlen("LOCATION_SCRIPT:"), value, length);
    artifact[strlen("LOCATION_SCRIPT:") + length] = '\0';
    return strchr(artifact + strlen("LOCATION_SCRIPT:"), '/') != NULL;
}

static BOOL canonical_mission_path(const char *path, char *output, size_t capacity) {
    char normalized[PATH_CAP];
    const char *name;
    if (!normalize_path(path, normalized, sizeof(normalized))) return FALSE;
    name = strstr(normalized, "data/missions/");
    if (name == NULL) return FALSE;
    name += strlen("data/missions/");
    return snprintf(output, capacity, "data/Missions/%s", name) > 0 &&
        strlen("data/Missions/") + strlen(name) + 1 <= capacity;
}

static BOOL semantic_alphabet(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    if (value == NULL || *value == '\0') return FALSE;
    while (*cursor != '\0') {
        if (!((*cursor >= 'a' && *cursor <= 'z') ||
              (*cursor >= 'A' && *cursor <= 'Z') ||
              (*cursor >= '0' && *cursor <= '9') ||
              strchr("_./:-#", *cursor) != NULL)) return FALSE;
        cursor++;
    }
    return TRUE;
}

static BOOL valid_sha256_text(const char *value) {
    size_t index;
    if (value == NULL || strlen(value) != 64) return FALSE;
    for (index = 0; index < 64; index++) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) return FALSE;
    }
    return TRUE;
}

static BOOL bounded_semantic_text(const char *value, size_t capacity) {
    size_t length = 0;
    if (value == NULL || capacity < 2) return FALSE;
    while (length < capacity && value[length] != '\0') length++;
    return length > 0 && length < capacity && semantic_alphabet(value);
}

static BOOL valid_mission_capture_target(const MvdsMissionCaptureTarget *mission) {
    MvdsCaptureHookFamily expected_family;
    const char *expected_opcode;
    if (mission == NULL || !bounded_semantic_text(mission->source_path, PATH_CAP) ||
        !bounded_semantic_text(mission->mission_key, 384) ||
        !bounded_semantic_text(mission->mission_phase, 16) ||
        !bounded_semantic_text(mission->opcode, 32) ||
        mission->mission_id == 0 || mission->native_action_ordinal >= 1024 ||
        (strcmp(mission->mission_phase,"activate") != 0 &&
         strcmp(mission->mission_phase,"complete") != 0 &&
         strcmp(mission->mission_phase,"reward") != 0)) return FALSE;
    switch (mission->route) {
        case MVDS_ROUTE_GROUND:
            expected_family = MVDS_CAPTURE_HOOK_ACTION_GROUND;
            expected_opcode = "PLAY_SCRIPT";
            break;
        case MVDS_ROUTE_BARN:
            expected_family = MVDS_CAPTURE_HOOK_ACTION_BARN;
            expected_opcode = "PLAY_BARNSCRIPT";
            break;
        case MVDS_ROUTE_FLIGHT:
            expected_family = MVDS_CAPTURE_HOOK_ACTION_FLIGHT;
            expected_opcode = "PLAY_SCRIPTMODEFLY";
            break;
        case MVDS_ROUTE_LOCATION_POLICY:
            expected_family = MVDS_CAPTURE_HOOK_ACTION_OUTRO;
            expected_opcode = "PLAY_OUTRO";
            break;
        default:
            return FALSE;
    }
    return mission->hook_family == expected_family &&
        strcmp(mission->opcode, expected_opcode) == 0;
}

static BOOL valid_location_capture_target(const MvdsLocationCaptureTarget *location) {
    if (location == NULL || location->location_id == 0 ||
        !bounded_semantic_text(location->selector, 160) ||
        !bounded_semantic_text(location->mode, 96)) return FALSE;
    switch (location->hook_family) {
        case MVDS_CAPTURE_HOOK_GENERIC_LOCATION_ENTER:
            return location->event_argument == -1 && location->location_id != 14 &&
                location->location_id != 20 && location->location_id != 22 &&
                (strcmp(location->selector,
                    "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3") == 0 ||
                 strcmp(location->selector,
                    "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3") == 0);
        case MVDS_CAPTURE_HOOK_GROTTE_STATE_SETTER:
            return location->event_argument == 5 && location->location_id == 10;
        case MVDS_CAPTURE_HOOK_RAYMOND_LOCATION_LOAD:
            return location->event_argument == -1 && location->location_id == 20;
        case MVDS_CAPTURE_HOOK_RAYMOND_STATE_SETTER:
            return location->event_argument == 6 && location->location_id == 20;
        case MVDS_CAPTURE_HOOK_EXHIBITION_STATE_SETTER:
            return location->event_argument == 6 && location->location_id == 14;
        case MVDS_CAPTURE_HOOK_MYGGHANGET_ENTER:
            return location->event_argument == -1 && location->location_id == 22;
        default:
            return FALSE;
    }
}

static BOOL create_capture_process_identity(void) {
    typedef BOOLEAN (WINAPI *RtlGenRandomFn)(PVOID, ULONG);
    HMODULE advapi;
    RtlGenRandomFn random_bytes;
    BYTE random[16];
    size_t index;
    int written;
    if (g_native_process_id != 0 || g_capture_session_id[0] != '\0') return FALSE;
    advapi = LoadLibraryA("advapi32.dll");
    if (!advapi) return FALSE;
    random_bytes = (RtlGenRandomFn)(uintptr_t)GetProcAddress(advapi,"SystemFunction036");
    if (!random_bytes || !random_bytes(random,sizeof(random))) {
        FreeLibrary(advapi);
        return FALSE;
    }
    FreeLibrary(advapi);
    memcpy(g_capture_session_id,"mvds-",5);
    for (index = 0; index < sizeof(random); ++index) {
        written = snprintf(g_capture_session_id + 5 + index * 2,
            sizeof(g_capture_session_id) - 5 - index * 2,"%02x",random[index]);
        if (written != 2) {
            memset(g_capture_session_id,0,sizeof(g_capture_session_id));
            return FALSE;
        }
    }
    g_capture_session_id[37] = '\0';
    g_native_process_id = GetCurrentProcessId();
    return g_native_process_id != 0;
}

BOOL mvds_configure_capture_target(const MvdsCaptureTarget *target) {
    if (target == NULL || g_armed || g_capture_target_configured ||
        target->driver_mode == NULL ||
        target->driver_bootstrap_profile_sha256 == NULL ||
        target->driver_scenario_sha256 == NULL ||
        target->driver_initial_user_sha256 == NULL ||
        !valid_sha256_text(target->plan_manifest_sha256) ||
        !valid_sha256_text(target->capture_plan_sha256) ||
        !bounded_semantic_text(target->job_id, CAPTURE_JOB_CAP) ||
        !valid_sha256_text(target->job_sha256) ||
        !bounded_semantic_text(target->claim_id, CAPTURE_JOB_CAP) ||
        !valid_sha256_text(target->claim_sha256) ||
        !valid_sha256_text(target->subject_sha256) ||
        !valid_sha256_text(target->expectation_sha256) ||
        !valid_sha256_text(target->scenario_sha256) ||
        !valid_sha256_text(target->native_slice_sha256) ||
        !valid_sha256_text(target->target_sha256)) return FALSE;
    if ((target->capture_driver != MVDS_CAPTURE_DRIVER_NONE &&
         (!valid_sha256_text(target->driver_bootstrap_profile_sha256) ||
          !valid_sha256_text(target->driver_scenario_sha256) ||
          !valid_sha256_text(target->driver_initial_user_sha256) ||
          !bounded_semantic_text(target->driver_mode, 64) ||
          strncmp(target->driver_mode, "mode_", 5) != 0)) ||
        (target->capture_driver ==
            MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2 &&
         (target->evidence_class != MVDS_EVIDENCE_LOCATION_POLICY ||
          target->trigger.location.hook_family !=
            MVDS_CAPTURE_HOOK_GENERIC_LOCATION_ENTER ||
          strcmp(target->trigger.location.selector,
            "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3") != 0 ||
          strcmp(target->driver_mode, target->trigger.location.mode) != 0)) ||
        (target->capture_driver ==
            MVDS_CAPTURE_DRIVER_BOOTSTRAP_TRAVERSAL_V1 &&
         (target->evidence_class != MVDS_EVIDENCE_LOCATION_POLICY ||
          target->trigger.location.hook_family !=
            MVDS_CAPTURE_HOOK_MYGGHANGET_ENTER ||
          strcmp(target->trigger.location.selector,
            "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE") != 0 ||
          strcmp(target->driver_mode, "mode_mygghanget") != 0)) ||
        (target->capture_driver ==
            MVDS_CAPTURE_DRIVER_MISSION_LOCATION_ENTER_V1 &&
         (target->evidence_class != MVDS_EVIDENCE_MISSION_DISPATCH ||
          target->trigger.mission.hook_family !=
            MVDS_CAPTURE_HOOK_ACTION_GROUND ||
          strcmp(target->trigger.mission.mission_phase, "activate") != 0)) ||
        (target->capture_driver ==
            MVDS_CAPTURE_DRIVER_MISSION_BARN_TRAVERSAL_V1 &&
         (target->evidence_class != MVDS_EVIDENCE_MISSION_DISPATCH ||
          target->trigger.mission.hook_family !=
            MVDS_CAPTURE_HOOK_ACTION_BARN ||
          strcmp(target->trigger.mission.mission_phase, "activate") != 0 ||
          strcmp(target->driver_mode, "mode_barn") != 0)) ||
        (target->capture_driver != MVDS_CAPTURE_DRIVER_NONE &&
         target->capture_driver !=
            MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2 &&
         target->capture_driver !=
            MVDS_CAPTURE_DRIVER_BOOTSTRAP_TRAVERSAL_V1 &&
         target->capture_driver !=
            MVDS_CAPTURE_DRIVER_MISSION_LOCATION_ENTER_V1 &&
         target->capture_driver !=
            MVDS_CAPTURE_DRIVER_MISSION_BARN_TRAVERSAL_V1) ||
        (target->capture_driver == MVDS_CAPTURE_DRIVER_NONE &&
         (strcmp(target->driver_mode, "-") != 0 ||
          strcmp(target->driver_bootstrap_profile_sha256, "-") != 0 ||
          strcmp(target->driver_scenario_sha256, "-") != 0 ||
          strcmp(target->driver_initial_user_sha256, "-") != 0)) ||
        (target->evidence_class == MVDS_EVIDENCE_MISSION_DISPATCH &&
         !valid_mission_capture_target(&target->trigger.mission)) ||
        (target->evidence_class == MVDS_EVIDENCE_LOCATION_POLICY &&
         !valid_location_capture_target(&target->trigger.location)) ||
        (target->evidence_class != MVDS_EVIDENCE_MISSION_DISPATCH &&
         target->evidence_class != MVDS_EVIDENCE_LOCATION_POLICY)) return FALSE;
    if (!create_capture_process_identity()) return FALSE;
    g_capture_target = *target;
    g_capture_target_configured = TRUE;
    return TRUE;
}

DWORD mvds_native_process_id(void) { return g_native_process_id; }

const char *mvds_capture_session_id(void) {
    return g_capture_session_id[0] != '\0' ? g_capture_session_id : NULL;
}

static void bind_mission(DWORD mission, const char *path) {
    size_t index;
    char canonical[PATH_CAP];
    if (!canonical_mission_path(path, canonical, sizeof(canonical))) return;
    EnterCriticalSection(&g_lock);
    for (index = 0; index < g_mission_count; index++) {
        if (g_missions[index].mission == mission) break;
    }
    if (index == g_mission_count) {
        if (g_mission_count == MISSION_CAP) {
            LeaveCriticalSection(&g_lock);
            fail_closed("mission pointer map exhausted");
            return;
        }
        g_mission_count++;
    }
    g_missions[index].mission = mission;
    strcpy(g_missions[index].path, canonical);
    LeaveCriticalSection(&g_lock);
}

static BOOL mission_path(DWORD mission, char *output, size_t capacity) {
    size_t index;
    BOOL found = FALSE;
    EnterCriticalSection(&g_lock);
    for (index = 0; index < g_mission_count; index++) {
        if (g_missions[index].mission == mission) {
            strncpy(output, g_missions[index].path, capacity - 1);
            output[capacity - 1] = '\0';
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&g_lock);
    return found;
}

static BOOL bind_root(DWORD root, const char *path) {
    size_t index;
    char artifact[ARTIFACT_CAP];
    if (root == 0 || !artifact_from_path(path, artifact, sizeof(artifact))) return FALSE;
    EnterCriticalSection(&g_lock);
    for (index = 0; index < g_root_count; index++) {
        if (g_roots[index].root == root) break;
    }
    if (index == g_root_count) {
        if (g_root_count == ROOT_CAP) {
            LeaveCriticalSection(&g_lock);
            fail_closed("root pointer map exhausted");
            return FALSE;
        }
        g_root_count++;
    }
    g_roots[index].root = root;
    strcpy(g_roots[index].artifact, artifact);
    LeaveCriticalSection(&g_lock);
    return TRUE;
}

static BOOL root_artifact(DWORD root, char *output, size_t capacity) {
    size_t index;
    BOOL found = FALSE;
    EnterCriticalSection(&g_lock);
    for (index = 0; index < g_root_count; index++) {
        if (g_roots[index].root == root) {
            strncpy(output, g_roots[index].artifact, capacity - 1);
            output[capacity - 1] = '\0';
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&g_lock);
    return found;
}

static const char *route_name(MvdsRoute route) {
    switch (route) {
        case MVDS_ROUTE_GROUND: return "GROUND";
        case MVDS_ROUTE_BARN: return "BARN";
        case MVDS_ROUTE_FLIGHT: return "FLIGHT";
        case MVDS_ROUTE_LOCATION_POLICY: return "LOCATION_POLICY";
        default: return "NONE";
    }
}

static const char *phase_name(DWORD phase) {
    switch (phase) {
        case 1: return "activate";
        case 2: return "complete";
        case 3: return "reward";
        default: return NULL;
    }
}

static BOOL action_ordinal(DWORD mission, DWORD node, DWORD *ordinal) {
    DWORD cursor = read_u32(mission + 0x30);
    DWORD index = 0, count = 0, found = (DWORD)-1;
    while (cursor != 0 && count < 1024) {
        if (cursor == node) found = index;
        cursor = read_u32(cursor + 0x1c);
        index++;
        count++;
    }
    if (cursor != 0 || found == (DWORD)-1) return FALSE;
    *ordinal = count - 1 - found;
    return TRUE;
}

static BOOL mission_identity(DWORD mission, char *key, size_t capacity,
    const char **phase, DWORD *ordinal, DWORD node, DWORD executor_phase) {
    DWORD id_object = read_u32(mission + 0x08);
    DWORD phase_object = read_u32(mission + 0x0c);
    DWORD id, phase_value;
    char path[PATH_CAP];
    if (!mission_path(mission, path, sizeof(path)) || id_object == 0 || phase_object == 0)
        return FALSE;
    id = read_u32(id_object + 0x114);
    phase_value = read_u32(phase_object + 0x114);
    if (phase_value != executor_phase || read_u32(node + 0x00) != executor_phase)
        return FALSE;
    *phase = phase_name(executor_phase);
    if (*phase == NULL || !action_ordinal(mission, node, ordinal)) return FALSE;
    return snprintf(key, capacity, "%lu:%s", (unsigned long)id, path) > 0;
}

static void emit_mission_event(const ActionFrame *frame) {
    char mission_key[384], artifact[ARTIFACT_CAP];
    const char *phase, *action;
    DWORD ordinal, sequence;
    if (!mission_identity(frame->mission, mission_key, sizeof(mission_key), &phase,
        &ordinal, frame->node, frame->executor_phase)) {
        fail_closed("mission dispatch lacks exact route, root, source, or ordinal provenance");
        return;
    }
    if (!g_capture_target_configured ||
        g_capture_target.evidence_class != MVDS_EVIDENCE_MISSION_DISPATCH ||
        g_capture_target.trigger.mission.route != frame->expected_route ||
        g_capture_target.trigger.mission.native_action_ordinal != ordinal ||
        strcmp(g_capture_target.trigger.mission.mission_key,mission_key) != 0 ||
        strcmp(g_capture_target.trigger.mission.mission_phase,phase) != 0) {
        fail_closed("mission dispatch differs from exact configured capture target");
        return;
    }
    if (frame->expected_route == MVDS_ROUTE_LOCATION_POLICY) {
        if (!frame->outro_commit_observed || frame->outro_object == 0 ||
            read_u8(frame->outro_object + 0x48ac) != 1) {
            fail_closed("PLAY_OUTRO lacks exact post-return location-policy commit");
            return;
        }
        strcpy(artifact, "LOCATION_SCRIPT:varldsutstallning/outro");
    } else if (frame->expected_route != frame->observed_route || frame->observed_root == 0 ||
        !root_artifact(frame->observed_root, artifact, sizeof(artifact))) {
        fail_closed("mission dispatch lacks exact route/root provenance");
        return;
    }
    if (!semantic_alphabet(mission_key) || !semantic_alphabet(artifact)) {
        fail_closed("mission dispatch identity contains non-canonical characters");
        return;
    }
    action = frame->expected_route == MVDS_ROUTE_GROUND ? "PREPENDED" :
        frame->expected_route == MVDS_ROUTE_LOCATION_POLICY ? "ARMED" : "STARTED";
    sequence = (DWORD)InterlockedIncrement(&g_sequence);
    if (emitf("{\"schema\":1,\"protocol\":\"%s\",\"record\":\"EVENT\","
        "\"executableSha256\":\"%s\",\"thread\":%lu,\"nativeProcessId\":%lu,"
        "\"captureSessionId\":\"%s\",\"evidenceClass\":\"MISSION_DISPATCH\","
        "\"receipt\":{\"schema\":1,\"sequence\":%lu,\"semanticStatus\":\"UNPROVEN\","
        "\"event\":{\"trigger\":\"MISSION_ACTION\",\"missionKey\":\"%s\",\"missionPhase\":\"%s\",\"nativeActionOrdinal\":%lu},"
        "\"before\":{\"sequence\":%lu},"
        "\"result\":{\"schema\":1,\"sequence\":%lu,\"trigger\":\"MISSION_ACTION\",\"action\":\"%s\",\"route\":\"%s\",\"locationId\":null,\"artifactKey\":\"%s\",\"duplicate\":false},"
        "\"after\":{\"sequence\":%lu,\"appliedMissionActions\":{\"%s|%s|%lu\":{\"action\":\"%s\",\"route\":\"%s\",\"locationId\":null,\"artifactKey\":\"%s\",\"duplicate\":false}}}}}",
        MVDS_PROTOCOL,MVDS_EXECUTABLE_SHA256,(unsigned long)GetCurrentThreadId(),
        (unsigned long)g_native_process_id,g_capture_session_id,
        (unsigned long)sequence,mission_key,phase,(unsigned long)ordinal,
        (unsigned long)(sequence-1),(unsigned long)sequence,action,route_name(frame->expected_route),artifact,
        (unsigned long)sequence,mission_key,phase,(unsigned long)ordinal,action,route_name(frame->expected_route),artifact))
        capture_event_complete();
}

static void emit_location_event(const char *selector, DWORD location, const char *artifact,
    BOOL root_complete, int final_state, int first_challenge, int challenge_result,
    int refuel_armed, int refuel_consumed, int outro_requested, BOOL projected_present,
    float projected_x, const char *action) {
    DWORD sequence;
    DWORD projected_bits = 0;
    char artifact_json[ARTIFACT_CAP + 8];
    char projected[64];
    char event_json[192];
#ifndef MVDS_TEST_MULTI_EMIT
    if (!g_capture_target_configured ||
        g_capture_target.evidence_class != MVDS_EVIDENCE_LOCATION_POLICY ||
        g_capture_target.trigger.location.location_id != location ||
        strcmp(g_capture_target.trigger.location.selector,selector) != 0) {
        fail_closed("location dispatch differs from exact configured capture target");
        return;
    }
#endif
    sequence = (DWORD)InterlockedIncrement(&g_sequence);
    if (!semantic_alphabet(selector) || (artifact != NULL && !semantic_alphabet(artifact))) {
        fail_closed("location dispatch identity contains non-canonical characters");
        return;
    }
    if (artifact == NULL) strcpy(artifact_json, "null");
    else snprintf(artifact_json, sizeof(artifact_json), "\"%s\"", artifact);
    if (projected_present && isfinite(projected_x)) {
        memcpy(&projected_bits, &projected_x, sizeof(projected_bits));
        snprintf(projected, sizeof(projected), "\"0x%08lx\"", (unsigned long)projected_bits);
    } else strcpy(projected, "null");
    if (root_complete) {
        snprintf(event_json, sizeof(event_json),
            "{\"trigger\":\"DERIVED_STATE\",\"kind\":\"ROOT_COMPLETE\",\"route\":\"GROUND\",\"locationId\":%lu}",
            (unsigned long)location);
    } else {
        snprintf(event_json, sizeof(event_json),
            "{\"trigger\":\"LOCATION_ENTER\",\"locationId\":%lu}",
            (unsigned long)location);
    }
    if (emitf("{\"schema\":1,\"protocol\":\"%s\",\"record\":\"EVENT\","
        "\"executableSha256\":\"%s\",\"thread\":%lu,\"nativeProcessId\":%lu,"
        "\"captureSessionId\":\"%s\",\"evidenceClass\":\"LOCATION_POLICY\",\"selector\":\"%s\","
        "\"receipt\":{\"schema\":1,\"sequence\":%lu,\"semanticStatus\":\"UNPROVEN\","
        "\"event\":%s,"
        "\"before\":{\"sequence\":%lu,\"finalMissionState\":%d,\"grotte\":{\"refuelArmed\":%s,\"refuelConsumed\":%s},"
        "\"raymond\":{\"firstChallenge\":%s,\"challengeResult\":%d},\"exhibition\":{\"outroRequested\":%s,\"projectedMapXBits\":%s}},"
        "\"result\":{\"schema\":1,\"sequence\":%lu,\"trigger\":\"%s\",\"action\":\"%s\",\"route\":\"GROUND\",\"locationId\":%lu,\"artifactKey\":%s},"
        "\"after\":{\"sequence\":%lu,\"locations\":{\"%lu\":{\"activeRoot\":%s}}}}}",
        MVDS_PROTOCOL,MVDS_EXECUTABLE_SHA256,(unsigned long)GetCurrentThreadId(),
        (unsigned long)g_native_process_id,g_capture_session_id,selector,
        (unsigned long)sequence,
        event_json,
        (unsigned long)(sequence-1), final_state,
        refuel_armed ? "true":"false",refuel_consumed ? "true":"false",
        first_challenge ? "true":"false",challenge_result,
        outro_requested ? "true":"false",projected,
        (unsigned long)sequence,root_complete ? "DERIVED_STATE":"LOCATION_ENTER",action,(unsigned long)location,artifact_json,
        (unsigned long)sequence,(unsigned long)location,artifact_json))
        capture_event_complete();
}

/* Generic locations need a dynamic location id; keep this separate from the
 * compact special-selector writer above. */
static void emit_generic_location(const char *selector, DWORD location, int final_state,
    const char *artifact) {
    DWORD sequence;
#ifndef MVDS_TEST_MULTI_EMIT
    if (!g_capture_target_configured ||
        g_capture_target.evidence_class != MVDS_EVIDENCE_LOCATION_POLICY ||
        g_capture_target.trigger.location.location_id != location ||
        strcmp(g_capture_target.trigger.location.selector,selector) != 0) {
        fail_closed("generic dispatch differs from exact configured capture target");
        return;
    }
#endif
    sequence = (DWORD)InterlockedIncrement(&g_sequence);
    if (!semantic_alphabet(selector) || !semantic_alphabet(artifact)) {
        fail_closed("generic dispatch identity contains non-canonical characters");
        return;
    }
    if (emitf("{\"schema\":1,\"protocol\":\"%s\",\"record\":\"EVENT\",\"executableSha256\":\"%s\","
        "\"thread\":%lu,\"nativeProcessId\":%lu,\"captureSessionId\":\"%s\","
        "\"evidenceClass\":\"LOCATION_POLICY\",\"selector\":\"%s\",\"receipt\":{"
        "\"schema\":1,\"sequence\":%lu,\"semanticStatus\":\"UNPROVEN\",\"event\":{\"trigger\":\"LOCATION_ENTER\",\"locationId\":%lu},"
        "\"before\":{\"sequence\":%lu,\"finalMissionState\":%d},\"result\":{\"schema\":1,\"sequence\":%lu,\"trigger\":\"LOCATION_ENTER\","
        "\"action\":\"STARTED\",\"route\":\"GROUND\",\"locationId\":%lu,\"artifactKey\":\"%s\"},"
        "\"after\":{\"sequence\":%lu,\"locations\":{\"%lu\":{\"activeRoot\":\"%s\"}}}}}",
        MVDS_PROTOCOL,MVDS_EXECUTABLE_SHA256,(unsigned long)GetCurrentThreadId(),
        (unsigned long)g_native_process_id,g_capture_session_id,selector,
        (unsigned long)sequence,(unsigned long)location,(unsigned long)(sequence-1),final_state,
        (unsigned long)sequence,(unsigned long)location,artifact,(unsigned long)sequence,(unsigned long)location,artifact))
        capture_event_complete();
}

BOOL mvds_read_final_mission_state(MvdsFinalMissionReadback *readback) {
    typedef void *(__cdecl *AppFn)(void);
    typedef void *(THISCALL *FindFn)(void *, int);
    typedef BYTE (THISCALL *CompleteFn)(void *);
    AppFn app_fn = (AppFn)(uintptr_t)0x00405a20;
    FindFn find_fn = (FindFn)(uintptr_t)0x004375e0;
    CompleteFn complete_fn = (CompleteFn)(uintptr_t)0x00436090;
    void *app;
    DWORD manager, mission;
    if (readback == NULL || !g_armed || !g_enabled || g_fatal ||
        GetCurrentThreadId() != g_host.engine_thread_id) return FALSE;
    memset(readback,0,sizeof(*readback));
    readback->state = -1;
    readback->application_getter_address = 0x00405a20u;
    readback->mission_lookup_address = 0x004375e0u;
    readback->mission_complete_address = 0x00436090u;
    app = app_fn();
    if (app == NULL) return TRUE;
    manager = read_u32((DWORD)(uintptr_t)app + 0x1ac);
    if (manager == 0) return TRUE;
    mission = (DWORD)(uintptr_t)find_fn((void *)(uintptr_t)(manager + 0x138), 9999);
    if (mission == 0) return TRUE;
    readback->mission_present = TRUE;
    readback->mission_address = mission;
    readback->state = complete_fn((void *)(uintptr_t)mission) ? 3 : 0;
    return TRUE;
}

BOOL mvds_completed_generic_readback(MvdsFinalMissionReadback *readback) {
    if (readback == NULL || !g_completed_generic_readback_valid ||
        !g_capture_event_emitted) return FALSE;
    *readback = g_completed_generic_readback;
    return TRUE;
}

BOOL mvds_mygghanget_absence_completed(void) {
    return g_capture_target_configured && !g_fatal &&
        g_capture_target.evidence_class == MVDS_EVIDENCE_LOCATION_POLICY &&
        g_capture_target.trigger.location.hook_family ==
            MVDS_CAPTURE_HOOK_MYGGHANGET_ENTER &&
        g_capture_event_emitted && !g_capture_window_active;
}

BOOL mvds_capture_event_completed(void) {
    return g_capture_target_configured && !g_fatal &&
        g_capture_event_emitted && !g_capture_window_active;
}

static int final_mission_state(void) {
    MvdsFinalMissionReadback readback;
    return mvds_read_final_mission_state(&readback) ? readback.state : -1;
}

static BOOL begin_capture_window_from_target_hook(MvdsCaptureHookFamily family) {
    BOOL opened;
    if (!engine_observation_ready() || !g_capture_target_configured ||
        g_capture_window_consumed) return FALSE;
    if ((g_capture_target.evidence_class == MVDS_EVIDENCE_MISSION_DISPATCH &&
         g_capture_target.trigger.mission.hook_family != family) ||
        (g_capture_target.evidence_class == MVDS_EVIDENCE_LOCATION_POLICY &&
         g_capture_target.trigger.location.hook_family != family)) return FALSE;
    g_target_hook_open_authorized = TRUE;
    opened = mvds_begin_capture_window();
    g_target_hook_open_authorized = FALSE;
    return opened;
}

static void capture_action(MvdsRoute route, DWORD node, DWORD mission) {
    DWORD last_error = GetLastError();
    char mission_key[384], source_path[PATH_CAP];
    const char *phase;
    DWORD ordinal, mission_id, id_object;
    const MvdsMissionCaptureTarget *target;
    if (engine_observation_ready() && g_action.active && g_action.node != 0) {
        fail_closed("duplicate action inline probe in executor interval");
        SetLastError(last_error); return;
    }
    if (!engine_observation_ready() || g_capture_window_consumed ||
        !g_capture_target_configured ||
        g_capture_target.evidence_class != MVDS_EVIDENCE_MISSION_DISPATCH) {
        SetLastError(last_error); return;
    }
    if (!g_action.active) {
        fail_closed("action inline probe fired outside executor interval");
        SetLastError(last_error);
        return;
    }
    if (node == 0 || mission == 0) {
        fail_closed("action inline probe lacks node or mission object");
        SetLastError(last_error);
        return;
    }
    target = &g_capture_target.trigger.mission;
    if (target->route != route || !mission_path(mission,source_path,sizeof(source_path)) ||
        !mission_identity(mission,mission_key,sizeof(mission_key),&phase,&ordinal,node,
            g_action.executor_phase)) {
        SetLastError(last_error); return;
    }
    id_object = read_u32(mission + 0x08);
    if (id_object == 0) { SetLastError(last_error); return; }
    mission_id = read_u32(id_object + 0x114);
    if (mission_id != target->mission_id || ordinal != target->native_action_ordinal ||
        strcmp(source_path,target->source_path) != 0 ||
        strcmp(mission_key,target->mission_key) != 0 ||
        strcmp(phase,target->mission_phase) != 0 ||
        !begin_capture_window_from_target_hook(target->hook_family)) {
        SetLastError(last_error); return;
    }
    g_action.node = node;
    g_action.mission = mission;
    g_action.expected_route = route;
    g_action.expected_object = read_u32(node + 0x10);
    if (g_action.expected_object == 0)
        fail_closed("action inline probe lacks dispatcher object provenance");
    SetLastError(last_error);
}

static void __cdecl ASM_USED capture_ground(DWORD mission, DWORD node) { capture_action(MVDS_ROUTE_GROUND,node,mission); }
static void __cdecl ASM_USED capture_barn(DWORD mission, DWORD node) { capture_action(MVDS_ROUTE_BARN,node,mission); }
static void __cdecl ASM_USED capture_flight(DWORD mission, DWORD node) { capture_action(MVDS_ROUTE_FLIGHT,node,mission); }
static void __cdecl ASM_USED capture_outro(DWORD mission, DWORD node) { capture_action(MVDS_ROUTE_LOCATION_POLICY,node,mission); }
static void __cdecl ASM_USED capture_outro_commit(DWORD object) {
    DWORD last_error = GetLastError();
    if (!on_engine_thread() || !g_action.active ||
        g_action.expected_route != MVDS_ROUTE_LOCATION_POLICY) {
        SetLastError(last_error); return;
    }
    if (g_action.outro_commit_observed) {
        fail_closed("duplicate PLAY_OUTRO commit probe");
        SetLastError(last_error); return;
    }
    if (object == 0 || object != g_action.expected_object) {
        fail_closed("PLAY_OUTRO commit object differs from action dispatcher");
        SetLastError(last_error); return;
    }
    g_action.outro_commit_observed = TRUE; g_action.outro_object = object;
    SetLastError(last_error);
}

#define ACTION_NAKED_BODY(helper, trampoline) __asm__ __volatile__( \
    "pushfl\n\tpushal\n\tmovl %esp,%ebx\n\tcld\n\t" \
    "subl $528,%esp\n\tandl $-16,%esp\n\tfxsave (%esp)\n\t" \
    "pushl 16(%ebx)\n\tpushl 0(%ebx)\n\tcall " helper "\n\taddl $8,%esp\n\t" \
    "fxrstor (%esp)\n\tmovl %ebx,%esp\n\tpopal\n\tpopfl\n\tjmp *" trampoline "")

static void NAKED hook_action_ground(void) { ACTION_NAKED_BODY("_capture_ground", "_g_action_ground_trampoline"); }
static void NAKED hook_action_barn(void) { ACTION_NAKED_BODY("_capture_barn", "_g_action_barn_trampoline"); }
static void NAKED hook_action_flight(void) { ACTION_NAKED_BODY("_capture_flight", "_g_action_flight_trampoline"); }
static void NAKED hook_action_outro(void) { ACTION_NAKED_BODY("_capture_outro", "_g_action_outro_trampoline"); }
static void NAKED hook_action_outro_commit(void) {
    __asm__ __volatile__(
        "pushfl\n\tpushal\n\tmovl %esp,%ebx\n\tcld\n\t"
        "subl $528,%esp\n\tandl $-16,%esp\n\tfxsave (%esp)\n\t"
        "pushl 28(%ebx)\n\tcall _capture_outro_commit\n\taddl $4,%esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx,%esp\n\tpopal\n\tpopfl\n\tjmp *_g_action_outro_commit_trampoline");
}

enum {
    SITE_GENERIC_FINAL_PRESENT = 1,
    SITE_GENERIC_FINAL_TRUE,
    SITE_GROTTE_REFUEL,
    SITE_RAYMOND_FIRST,
    SITE_RAYMOND_RESULT,
    SITE_EXHIBITION_LT_2200,
    SITE_EXHIBITION_LT_900_SELECTED,
    SITE_EXHIBITION_LT_2200_SELECTED,
    SITE_EXHIBITION_LT_2200_FINAL_TRUE,
    SITE_EXHIBITION_GTE_2200,
    SITE_EXHIBITION_GTE_2200_FINAL_TRUE,
    SITE_EXHIBITION_FINAL_FALSE,
    SITE_EXHIBITION_OUTRO,
    SITE_EXHIBITION_PROJECTION
};

enum {
    EXHIBITION_TERMINAL_NONE = 0,
    EXHIBITION_TERMINAL_LT_900,
    EXHIBITION_TERMINAL_LT_2200,
    EXHIBITION_TERMINAL_GTE_2200,
    EXHIBITION_TERMINAL_OUTRO
};

static SelectorKind selector_kind_for_site(int site) {
    switch (site) {
        case SITE_GENERIC_FINAL_PRESENT:
        case SITE_GENERIC_FINAL_TRUE:
            return SELECTOR_GENERIC;
        case SITE_GROTTE_REFUEL:
            return SELECTOR_GROTTE;
        case SITE_RAYMOND_FIRST:
            return SELECTOR_RAYMOND_ENTRY;
        case SITE_RAYMOND_RESULT:
            return SELECTOR_RAYMOND_RESULT;
        case SITE_EXHIBITION_LT_2200:
        case SITE_EXHIBITION_LT_900_SELECTED:
        case SITE_EXHIBITION_LT_2200_SELECTED:
        case SITE_EXHIBITION_LT_2200_FINAL_TRUE:
        case SITE_EXHIBITION_GTE_2200:
        case SITE_EXHIBITION_GTE_2200_FINAL_TRUE:
        case SITE_EXHIBITION_FINAL_FALSE:
        case SITE_EXHIBITION_OUTRO:
        case SITE_EXHIBITION_PROJECTION:
            return SELECTOR_EXHIBITION;
        default:
            return SELECTOR_NONE;
    }
}

static void __cdecl ASM_USED capture_selector_site(int site, DWORD object, DWORD value) {
    DWORD last_error = GetLastError();
    SelectorKind expected_kind;
    (void)value;
    if (!on_engine_thread()) { SetLastError(last_error); return; }
    if (g_selector.kind == SELECTOR_NONE) {
        fail_closed("selector inline probe fired outside selector interval");
        SetLastError(last_error); return;
    }
    if (object == 0 || object != g_selector.object) {
        fail_closed("selector inline probe object differs from interval object");
        SetLastError(last_error); return;
    }
    expected_kind = selector_kind_for_site(site);
    if (expected_kind == SELECTOR_NONE) {
        fail_closed("unknown selector inline site");
        SetLastError(last_error); return;
    }
    if (g_selector.kind != expected_kind) {
        fail_closed("selector inline probe fired in wrong typed interval");
        SetLastError(last_error); return;
    }
    switch (site) {
        case SITE_GENERIC_FINAL_PRESENT:
            if (g_selector.kind == SELECTOR_GENERIC && g_selector.final_mission_present)
                fail_closed("duplicate generic final-mission-present probe");
            else if (g_selector.kind == SELECTOR_GENERIC)
                g_selector.final_mission_present = TRUE;
            break;
        case SITE_GENERIC_FINAL_TRUE:
            if (g_selector.kind == SELECTOR_GENERIC) {
                if (!g_selector.final_mission_present)
                    fail_closed("generic final predicate fired without mission-present branch");
                else if (g_selector.final_predicate_observed)
                    fail_closed("duplicate generic final predicate probe");
                else {
                    g_selector.final_predicate_observed = TRUE;
                    g_selector.final_mission_complete = TRUE;
                }
            }
            break;
        case SITE_GROTTE_REFUEL:
            if (g_selector.kind == SELECTOR_GROTTE) {
                if (g_selector.predicate_site_observed)
                    fail_closed("duplicate grotte predicate probe");
                else {
                    g_selector.predicate_site_observed = TRUE;
                    g_selector.observed_predicate_value = read_u8(object + 0x48a4) != 0;
                    g_selector.observed_result = read_u8(object + 0x48a5) != 0;
                }
            }
            break;
        case SITE_RAYMOND_FIRST:
            if (g_selector.kind == SELECTOR_RAYMOND_ENTRY) {
                if (g_selector.predicate_site_observed)
                    fail_closed("duplicate Raymond-entry predicate probe");
                else {
                    g_selector.predicate_site_observed = TRUE;
                    g_selector.observed_predicate_value = read_u8(object + 0x489c) != 0;
                }
            }
            break;
        case SITE_RAYMOND_RESULT:
            if (g_selector.kind == SELECTOR_RAYMOND_RESULT) {
                if (g_selector.predicate_site_observed)
                    fail_closed("duplicate Raymond-result predicate probe");
                else {
                    g_selector.predicate_site_observed = TRUE;
                    g_selector.observed_predicate_value = read_u8(object + 0x4894) != 0;
                    g_selector.observed_result = (int)read_u32(object + 0x4898);
                }
            }
            break;
        case SITE_EXHIBITION_LT_2200:
            if (g_selector.kind == SELECTOR_EXHIBITION &&
                g_selector.secondary_predicate_site_observed)
                fail_closed("duplicate exhibition LT2200 comparison probe");
            else if (g_selector.kind == SELECTOR_EXHIBITION)
                g_selector.secondary_predicate_site_observed = TRUE;
            break;
        case SITE_EXHIBITION_LT_900_SELECTED:
            if (g_selector.kind == SELECTOR_EXHIBITION &&
                g_selector.terminal_branch != EXHIBITION_TERMINAL_NONE)
                fail_closed("duplicate exhibition terminal branch probe");
            else if (g_selector.kind == SELECTOR_EXHIBITION)
                g_selector.terminal_branch = EXHIBITION_TERMINAL_LT_900;
            break;
        case SITE_EXHIBITION_LT_2200_SELECTED:
            if (g_selector.kind == SELECTOR_EXHIBITION &&
                g_selector.terminal_branch != EXHIBITION_TERMINAL_NONE)
                fail_closed("duplicate exhibition terminal branch probe");
            else if (g_selector.kind == SELECTOR_EXHIBITION)
                g_selector.terminal_branch = EXHIBITION_TERMINAL_LT_2200;
            break;
        case SITE_EXHIBITION_LT_2200_FINAL_TRUE:
            if (g_selector.kind == SELECTOR_EXHIBITION &&
                g_selector.terminal_branch == EXHIBITION_TERMINAL_LT_2200) {
                if (g_selector.final_predicate_observed)
                    fail_closed("duplicate exhibition LT2200 final predicate probe");
                else {
                    g_selector.final_predicate_observed = TRUE;
                    g_selector.final_mission_complete = TRUE;
                }
            } else fail_closed("exhibition LT2200 true branch lacks matching terminal branch");
            break;
        case SITE_EXHIBITION_GTE_2200:
            if (g_selector.kind == SELECTOR_EXHIBITION &&
                g_selector.terminal_branch != EXHIBITION_TERMINAL_NONE)
                fail_closed("duplicate exhibition terminal branch probe");
            else if (g_selector.kind == SELECTOR_EXHIBITION)
                g_selector.terminal_branch = EXHIBITION_TERMINAL_GTE_2200;
            break;
        case SITE_EXHIBITION_GTE_2200_FINAL_TRUE:
            if (g_selector.kind == SELECTOR_EXHIBITION &&
                g_selector.terminal_branch == EXHIBITION_TERMINAL_GTE_2200) {
                if (g_selector.final_predicate_observed)
                    fail_closed("duplicate exhibition GTE2200 final predicate probe");
                else {
                    g_selector.final_predicate_observed = TRUE;
                    g_selector.final_mission_complete = TRUE;
                }
            } else fail_closed("exhibition GTE2200 true branch lacks matching terminal branch");
            break;
        case SITE_EXHIBITION_FINAL_FALSE:
            if (g_selector.kind == SELECTOR_EXHIBITION &&
                (g_selector.terminal_branch == EXHIBITION_TERMINAL_LT_2200 ||
                 g_selector.terminal_branch == EXHIBITION_TERMINAL_GTE_2200)) {
                if (g_selector.final_predicate_observed)
                    fail_closed("duplicate exhibition false final predicate probe");
                else {
                    g_selector.final_predicate_observed = TRUE;
                    g_selector.final_mission_complete = FALSE;
                }
            } else fail_closed("exhibition false branch lacks matching terminal branch");
            break;
        case SITE_EXHIBITION_OUTRO:
            if (g_selector.kind == SELECTOR_EXHIBITION &&
                g_selector.terminal_branch != EXHIBITION_TERMINAL_NONE)
                fail_closed("duplicate exhibition terminal branch probe");
            else if (g_selector.kind == SELECTOR_EXHIBITION)
                g_selector.terminal_branch = EXHIBITION_TERMINAL_OUTRO;
            break;
        case SITE_EXHIBITION_PROJECTION:
            if (g_selector.kind == SELECTOR_EXHIBITION && g_selector.projection_site_observed)
                fail_closed("duplicate exhibition projection probe");
            else if (g_selector.kind == SELECTOR_EXHIBITION)
                g_selector.projection_site_observed = TRUE;
            break;
        default:
            fail_closed("unreachable selector inline site");
    }
    SetLastError(last_error);
}

#define SELECTOR_NAKED_BODY(site, trampoline) __asm__ __volatile__( \
    "pushfl\n\tpushal\n\tmovl %esp,%ebx\n\tcld\n\t" \
    "subl $528,%esp\n\tandl $-16,%esp\n\tfxsave (%esp)\n\t" \
    "pushl 28(%ebx)\n\tpushl 4(%ebx)\n\tpushl $" site "\n\t" \
    "call _capture_selector_site\n\taddl $12,%esp\n\t" \
    "fxrstor (%esp)\n\tmovl %ebx,%esp\n\tpopal\n\tpopfl\n\tjmp *" trampoline "")

static void NAKED hook_generic_final_mission_present(void) { SELECTOR_NAKED_BODY("1", "_g_generic_final_mission_present_trampoline"); }
static void NAKED hook_generic_final_true(void) { SELECTOR_NAKED_BODY("2", "_g_generic_final_true_trampoline"); }
static void NAKED hook_grotte_refuel_branch(void) { SELECTOR_NAKED_BODY("3", "_g_grotte_refuel_branch_trampoline"); }
static void NAKED hook_raymond_first_branch(void) { SELECTOR_NAKED_BODY("4", "_g_raymond_first_branch_trampoline"); }
static void NAKED hook_raymond_result_branch(void) { SELECTOR_NAKED_BODY("5", "_g_raymond_result_branch_trampoline"); }
static void NAKED hook_exhibition_lt_2200(void) { SELECTOR_NAKED_BODY("6", "_g_exhibition_lt_2200_trampoline"); }
static void NAKED hook_exhibition_lt_900_selected(void) { SELECTOR_NAKED_BODY("7", "_g_exhibition_lt_900_selected_trampoline"); }
static void NAKED hook_exhibition_lt_2200_selected(void) { SELECTOR_NAKED_BODY("8", "_g_exhibition_lt_2200_selected_trampoline"); }
static void NAKED hook_exhibition_lt_2200_final_true(void) { SELECTOR_NAKED_BODY("9", "_g_exhibition_lt_2200_final_true_trampoline"); }
static void NAKED hook_exhibition_gte_2200(void) { SELECTOR_NAKED_BODY("10", "_g_exhibition_gte_2200_trampoline"); }
static void NAKED hook_exhibition_gte_2200_final_true(void) { SELECTOR_NAKED_BODY("11", "_g_exhibition_gte_2200_final_true_trampoline"); }
static void NAKED hook_exhibition_final_false(void) { SELECTOR_NAKED_BODY("12", "_g_exhibition_final_false_trampoline"); }
static void NAKED hook_exhibition_outro(void) { SELECTOR_NAKED_BODY("13", "_g_exhibition_outro_trampoline"); }
static void NAKED hook_exhibition_projection(void) { SELECTOR_NAKED_BODY("14", "_g_exhibition_projection_trampoline"); }

static void __cdecl ASM_USED capture_projected_x(DWORD bits) {
    DWORD last_error = GetLastError();
    float value;
    memcpy(&value, &bits, sizeof(value));
    if (!on_engine_thread() || g_selector.kind != SELECTOR_EXHIBITION) {
        SetLastError(last_error); return;
    }
    if (g_selector.object == 0 || !g_selector.projection_site_observed) {
        fail_closed("projected-X probe lacks exact exhibition projection interval");
        SetLastError(last_error); return;
    }
    if (g_selector.projected_x_observed) {
        fail_closed("duplicate projected-X probe");
        SetLastError(last_error); return;
    }
    if (!isfinite(value)) {
        fail_closed("exhibition projectedMapX is non-finite");
        SetLastError(last_error);
        return;
    }
    g_selector.projected_x_observed = TRUE;
    g_selector.predicate_site_observed = TRUE;
    g_selector.projected_x = value;
    SetLastError(last_error);
}

static void NAKED hook_exhibition_projected_x(void) {
    __asm__ __volatile__(
        "pushfl\n\tpushal\n\tmovl %esp,%ebx\n\tcld\n\t"
        "subl $528,%esp\n\tandl $-16,%esp\n\tfxsave (%esp)\n\t"
        "movl 12(%ebx),%eax\n\taddl $16,%eax\n\tpushl (%eax)\n\t"
        "call _capture_projected_x\n\taddl $4,%esp\n\t"
        "fxrstor (%esp)\n\tmovl %ebx,%esp\n\tpopal\n\tpopfl\n\tjmp *_g_exhibition_projected_x_trampoline");
}

static void *MVDS_FASTCALL hook_parse(void *self, DWORD ignored, DWORD arg, const char *path) {
    char raw[PATH_CAP];
    MissionSourceSlot *slot;
    BOOL owns_interval = FALSE;
    DWORD incoming_error = GetLastError();
    void *result;
    (void)ignored;
    /* Native explicitly accepts a null path and returns without parsing.
     * That startup probe owns no source interval and must pass through. */
    slot = mission_source_tracking_required() && path != NULL ?
        mission_source_slot(TRUE) : NULL;
    if (slot != NULL) {
        if (slot->active || slot->depth != 0) {
            slot->depth++;
            fail_closed("nested mission parse source interval");
        } else {
            owns_interval = TRUE;
            slot->active = TRUE;
            slot->depth = 1;
            slot->container = (DWORD)(uintptr_t)self;
            slot->insert_count = 0;
            slot->path[0] = '\0';
            if (!copy_remote_string(path, raw, sizeof(raw)))
                fail_closed("mission parse source path is unreadable or unterminated");
            else if (!canonical_mission_path(raw, slot->path, sizeof(slot->path)))
                fail_closed("mission parse path is not canonical");
        }
    }
    SetLastError(incoming_error);
    result = g_parse_trampoline(self, arg, path);
    incoming_error = GetLastError();
    if (slot != NULL && !owns_interval && slot->depth > 1) {
        slot->depth--;
    } else if (slot != NULL && owns_interval && slot->active &&
        slot->container == (DWORD)(uintptr_t)self && slot->depth == 1) {
        if (slot->insert_count != 1)
            fail_closed("mission parse interval did not bind exactly one mission insert");
        slot->active = FALSE;
        slot->depth = 0;
        slot->container = 0;
        slot->insert_count = 0;
        slot->path[0] = '\0';
    }
    SetLastError(incoming_error);
    return result;
}

static void MVDS_FASTCALL hook_insert(void *self, DWORD ignored, void *mission) {
    MissionSourceSlot *slot;
    BOOL tracking = mission_source_tracking_required();
    DWORD incoming_error = GetLastError();
    (void)ignored;
    slot = tracking ? mission_source_slot(FALSE) : NULL;
    if (tracking && (slot == NULL || !slot->active || slot->depth != 1 ||
        slot->container != (DWORD)(uintptr_t)self || slot->path[0] == '\0')) {
        fail_closed("mission insert lacks matching active parse source interval");
    } else if (slot != NULL) {
        if (slot->insert_count != 0) fail_closed("duplicate mission insert in parse interval");
        else {
            bind_mission((DWORD)(uintptr_t)mission, slot->path);
            slot->insert_count = 1;
        }
    }
    SetLastError(incoming_error);
    g_insert_trampoline(self, mission);
}

static void MVDS_FASTCALL hook_executor(void *self, DWORD ignored, DWORD phase) {
    ActionFrame completed;
    BOOL opened;
    DWORD incoming_error = GetLastError(), outgoing_error;
    (void)ignored;
    if (!engine_observation_ready()) { SetLastError(incoming_error); g_executor_trampoline(self,phase); return; }
    if (g_action.active) { fail_closed("nested mission executor interval"); SetLastError(incoming_error); g_executor_trampoline(self,phase); return; }
    memset(&g_action, 0, sizeof(g_action));
    g_action.active = TRUE;
    g_action.executor_phase = phase;
    SetLastError(incoming_error);
    g_executor_trampoline(self,phase);
    outgoing_error = GetLastError();
    completed = g_action;
    memset(&g_action, 0, sizeof(g_action));
    opened = g_capture_window_consumed &&
        g_capture_target.evidence_class == MVDS_EVIDENCE_MISSION_DISPATCH &&
        completed.node != 0;
    if (completed.node != 0 && read_u8(completed.node + 0x18) == 1)
        emit_mission_event(&completed);
    if (opened) mvds_end_capture_window();
    SetLastError(outgoing_error);
}

static void *__cdecl hook_root_factory(void *owner, const char *path) {
    char raw[PATH_CAP], artifact[ARTIFACT_CAP];
    void *root;
    BOOL copied = FALSE, bound = FALSE;
    DWORD incoming_error = GetLastError(), outgoing_error;
    if (g_armed) copied = copy_remote_string(path, raw, sizeof(raw));
    SetLastError(incoming_error);
    root = g_root_factory_trampoline(owner, path);
    outgoing_error = GetLastError();
    if (g_armed) {
        if (copied) bound = bind_root((DWORD)(uintptr_t)root, raw);
        if (g_selector.kind == SELECTOR_MYGGHANGET) {
            if (!copied || !bound) {
                g_selector.root_without_provenance = TRUE;
            } else if (artifact_from_path(raw, artifact, sizeof(artifact)) &&
                strncmp(artifact, "LOCATION_SCRIPT:mygghanget/",
                    strlen("LOCATION_SCRIPT:mygghanget/")) == 0) {
                g_selector.mygghanget_root_created = TRUE;
            }
        }
    }
    SetLastError(outgoing_error);
    return root;
}

static BOOL location_target_matches(MvdsCaptureHookFamily family, DWORD location, int event) {
    const MvdsLocationCaptureTarget *target;
    if (!engine_observation_ready() || g_capture_window_consumed ||
        !g_capture_target_configured ||
        g_capture_target.evidence_class != MVDS_EVIDENCE_LOCATION_POLICY) return FALSE;
    target = &g_capture_target.trigger.location;
    return target->hook_family == family && target->location_id == location &&
        target->event_argument == event;
}

static void MVDS_FASTCALL hook_generic_enter(void *self, DWORD ignored) {
    int final_state;
    DWORD location, active;
    DWORD incoming_error = GetLastError(), outgoing_error;
    SelectorFrame completed;
    char artifact[ARTIFACT_CAP];
    const char *selector;
    BOOL opened = FALSE;
    MvdsFinalMissionReadback hook_readback;
    (void)ignored;
    if (!engine_observation_ready() || g_selector.kind == SELECTOR_MYGGHANGET) {
        SetLastError(incoming_error); g_generic_enter_trampoline(self); return;
    }
    location = read_u32((DWORD)(uintptr_t)self + 0x4c);
    if (location == 14) {
        if (g_capture_target_configured && !g_capture_window_consumed &&
            g_capture_target.evidence_class == MVDS_EVIDENCE_LOCATION_POLICY &&
            g_capture_target.trigger.location.hook_family ==
                MVDS_CAPTURE_HOOK_EXHIBITION_STATE_SETTER) {
            if (g_exhibition_entry.active)
                fail_closed("duplicate exhibition entry interval");
            else {
                g_exhibition_entry.active = TRUE;
                g_exhibition_entry.object = (DWORD)(uintptr_t)self;
                g_exhibition_entry.thread_id = GetCurrentThreadId();
            }
        }
        SetLastError(incoming_error);
        g_generic_enter_trampoline(self);
        outgoing_error = GetLastError();
        SetLastError(outgoing_error);
        return;
    }
    if (g_exhibition_entry.active)
        fail_closed("stale exhibition entry interval before generic entry");
    if (!location_target_matches(MVDS_CAPTURE_HOOK_GENERIC_LOCATION_ENTER,location,-1)) {
        SetLastError(incoming_error); g_generic_enter_trampoline(self); return;
    }
    opened = begin_capture_window_from_target_hook(
        MVDS_CAPTURE_HOOK_GENERIC_LOCATION_ENTER);
    if (!opened) {
        SetLastError(incoming_error); g_generic_enter_trampoline(self); return;
    }
    if (g_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2 &&
        (!mvds_read_final_mission_state(&hook_readback) ||
         hook_readback.state == 3)) {
        fail_closed("generic clean driver final mission precondition differs");
    }
    begin_selector(SELECTOR_GENERIC,self);
    SetLastError(incoming_error);
    g_generic_enter_trampoline(self);
    outgoing_error = GetLastError();
    completed = g_selector; end_selector();
    active = read_u32((DWORD)(uintptr_t)self + 0x8d4);
    /* The mission-present probe brackets the native completion call.  Its
     * taken true branch has a dedicated instruction-safe probe; returning
     * without that probe is therefore the exact false result. */
    if (completed.final_mission_present && !completed.final_predicate_observed)
        completed.final_predicate_observed = TRUE;
    final_state = completed.final_mission_complete ? 3 : 0;
    if (
        !root_artifact(active, artifact, sizeof(artifact))) {
        fail_closed("generic location selector lacks root provenance");
        mvds_end_capture_window();
        SetLastError(outgoing_error); return;
    }
    selector = final_state == 3 ? "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3" :
        "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3";
    if (g_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2 &&
        (final_state == 3 || hook_readback.state == 3)) {
        fail_closed("generic clean driver final mission hook readback differs");
        mvds_end_capture_window();
        SetLastError(outgoing_error); return;
    }
    if (g_capture_target.capture_driver ==
            MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2) {
        g_completed_generic_readback = hook_readback;
        g_completed_generic_readback_valid = TRUE;
    }
    emit_generic_location(selector, location, final_state, artifact);
    mvds_end_capture_window();
    SetLastError(outgoing_error);
}

static void begin_selector(SelectorKind kind, void *self) {
    if (g_selector.kind != SELECTOR_NONE) { fail_closed("nested selector interval"); return; }
    memset(&g_selector, 0, sizeof(g_selector));
    g_selector.kind = kind;
    g_selector.object = (DWORD)(uintptr_t)self;
}

static void end_selector(void) { memset(&g_selector, 0, sizeof(g_selector)); }

static void MVDS_FASTCALL hook_grotte_setter(void *self, DWORD ignored, int event) {
    int armed, consumed, final_state;
    SelectorFrame completed;
    char artifact[ARTIFACT_CAP];
    DWORD incoming_error = GetLastError(), outgoing_error;
    BOOL opened;
    (void)ignored;
    if (!location_target_matches(MVDS_CAPTURE_HOOK_GROTTE_STATE_SETTER,10,event)) {
        SetLastError(incoming_error); g_grotte_setter_trampoline(self,event); return;
    }
    armed = read_u8((DWORD)(uintptr_t)self + 0x48a4) != 0;
    consumed = read_u8((DWORD)(uintptr_t)self + 0x48a5) != 0;
    final_state = final_mission_state();
    opened = begin_capture_window_from_target_hook(MVDS_CAPTURE_HOOK_GROTTE_STATE_SETTER);
    if (!opened) {
        SetLastError(incoming_error); g_grotte_setter_trampoline(self,event); return;
    }
    begin_selector(SELECTOR_GROTTE,self);
    SetLastError(incoming_error);
    g_grotte_setter_trampoline(self,event);
    outgoing_error = GetLastError();
    completed = g_selector; end_selector();
    if (!completed.predicate_site_observed ||
        completed.observed_predicate_value != armed ||
        completed.observed_result != consumed) {
        fail_closed("grotte event-5 predicate probe is absent or mismatched");
    } else if (armed && !consumed) {
        if (completed.observed_route != MVDS_ROUTE_GROUND ||
            !root_artifact(completed.observed_root, artifact, sizeof(artifact)))
            fail_closed("grotte refuel branch lacks exact route/root provenance");
        else
            emit_location_event("ROOT_COMPLETE_REFUEL_ARMED_AND_UNCONSUMED",10,artifact,TRUE,
                final_state,0,0,armed,consumed,0,FALSE,0.0f,"ADVANCED");
    } else if (completed.observed_route != MVDS_ROUTE_NONE) {
        fail_closed("grotte non-selected predicate unexpectedly dispatched a route");
    }
    mvds_end_capture_window();
    SetLastError(outgoing_error);
}

static BYTE MVDS_FASTCALL hook_raymond_load(void *self, DWORD ignored, DWORD argument) {
    int first, final_state;
    DWORD selected;
    BYTE native_result;
    DWORD incoming_error = GetLastError(), outgoing_error;
    SelectorFrame completed;
    char artifact[ARTIFACT_CAP];
    const char *selector;
    BOOL opened;
    (void)ignored;
    if (!location_target_matches(MVDS_CAPTURE_HOOK_RAYMOND_LOCATION_LOAD,20,-1)) {
        SetLastError(incoming_error);
        return g_raymond_load_trampoline(self,argument);
    }
    final_state = final_mission_state();
    opened = begin_capture_window_from_target_hook(MVDS_CAPTURE_HOOK_RAYMOND_LOCATION_LOAD);
    if (!opened) {
        SetLastError(incoming_error);
        return g_raymond_load_trampoline(self,argument);
    }
    begin_selector(SELECTOR_RAYMOND_ENTRY,self);
    SetLastError(incoming_error);
    native_result = g_raymond_load_trampoline(self,argument);
    outgoing_error = GetLastError();
    completed = g_selector; end_selector();
    if (!completed.predicate_site_observed) {
        if (native_result == 0) {
            mvds_end_capture_window(); SetLastError(outgoing_error); return native_result;
        }
        fail_closed("Raymond entry did not execute the pinned firstChallenge branch");
        mvds_end_capture_window();
        SetLastError(outgoing_error); return native_result;
    }
    first = completed.observed_predicate_value;
    selected = read_u32((DWORD)(uintptr_t)self + 0x8d0);
    if (!root_artifact(selected,artifact,sizeof(artifact))) {
        fail_closed("Raymond entry root lacks factory provenance");
        mvds_end_capture_window();
        SetLastError(outgoing_error); return native_result;
    }
    selector = first ? "LOCATION_ENTER_FIRST_CHALLENGE" : "LOCATION_ENTER_SUBSEQUENT_CHALLENGE";
    emit_location_event(selector,20,artifact,FALSE,final_state,first,0,0,0,0,FALSE,0.0f,"STARTED");
    mvds_end_capture_window();
    SetLastError(outgoing_error);
    return native_result;
}

static void MVDS_FASTCALL hook_raymond_setter(void *self, DWORD ignored, int event) {
    int result, active, final_state;
    SelectorFrame completed;
    char artifact[ARTIFACT_CAP];
    const char *selector;
    DWORD incoming_error = GetLastError(), outgoing_error;
    BOOL opened;
    (void)ignored;
    if (!location_target_matches(MVDS_CAPTURE_HOOK_RAYMOND_STATE_SETTER,20,event)) {
        SetLastError(incoming_error); g_raymond_setter_trampoline(self,event); return;
    }
    active = read_u8((DWORD)(uintptr_t)self + 0x4894) != 0;
    result = (int)read_u32((DWORD)(uintptr_t)self + 0x4898);
    final_state = final_mission_state();
    opened = begin_capture_window_from_target_hook(MVDS_CAPTURE_HOOK_RAYMOND_STATE_SETTER);
    if (!opened) {
        SetLastError(incoming_error); g_raymond_setter_trampoline(self,event); return;
    }
    begin_selector(SELECTOR_RAYMOND_RESULT,self);
    SetLastError(incoming_error);
    g_raymond_setter_trampoline(self,event);
    outgoing_error = GetLastError();
    completed = g_selector; end_selector();
    if (!completed.predicate_site_observed ||
        completed.observed_predicate_value != active ||
        completed.observed_result != result) {
        fail_closed("Raymond event-6 predicate probe is absent or mismatched");
    } else if (!active) {
        if (completed.observed_route != MVDS_ROUTE_GROUND ||
            !root_artifact(completed.observed_root,artifact,sizeof(artifact)))
            fail_closed("Raymond completion branch lacks exact route/root provenance");
        else {
            selector = result == 2 ? "CHALLENGE_ROOT_COMPLETE_RESULT_EQ_2" : "CHALLENGE_ROOT_COMPLETE_RESULT_NE_2";
            emit_location_event(selector,20,artifact,TRUE,final_state,0,result,0,0,0,FALSE,0.0f,"ADVANCED");
        }
    } else if (completed.observed_route != MVDS_ROUTE_NONE) {
        fail_closed("Raymond active challenge unexpectedly dispatched a completion route");
    }
    mvds_end_capture_window();
    SetLastError(outgoing_error);
}

static void MVDS_FASTCALL hook_exhibition_setter(void *self, DWORD ignored, int event) {
    int outro, final_state;
    DWORD incoming_error = GetLastError(), outgoing_error;
    SelectorFrame completed;
    char artifact[ARTIFACT_CAP];
    const char *selector;
    BOOL opened;
    (void)ignored;
    if (!location_target_matches(MVDS_CAPTURE_HOOK_EXHIBITION_STATE_SETTER,14,event)) {
        SetLastError(incoming_error); g_exhibition_setter_trampoline(self,event); return;
    }
    if (!g_exhibition_entry.active ||
        g_exhibition_entry.thread_id != GetCurrentThreadId() ||
        g_exhibition_entry.object != (DWORD)(uintptr_t)self) {
        fail_closed("exhibition setter lacks matching location-14 entry interval");
        SetLastError(incoming_error);
        g_exhibition_setter_trampoline(self,event);
        return;
    }
    outro = read_u8((DWORD)(uintptr_t)self + 0x48ac) != 0;
    opened = begin_capture_window_from_target_hook(
        MVDS_CAPTURE_HOOK_EXHIBITION_STATE_SETTER);
    if (!opened) {
        SetLastError(incoming_error); g_exhibition_setter_trampoline(self,event); return;
    }
    begin_selector(SELECTOR_EXHIBITION,self);
    SetLastError(incoming_error);
    g_exhibition_setter_trampoline(self,event);
    outgoing_error = GetLastError();
    completed = g_selector; end_selector();
    memset(&g_exhibition_entry, 0, sizeof(g_exhibition_entry));
    if (completed.observed_route != MVDS_ROUTE_GROUND ||
        !root_artifact(completed.observed_root,artifact,sizeof(artifact))) {
        fail_closed("exhibition terminal route lacks exact root provenance");
        mvds_end_capture_window();
        SetLastError(outgoing_error); return;
    }
    if (outro) {
        if (completed.terminal_branch != EXHIBITION_TERMINAL_OUTRO) {
            fail_closed("exhibition outro terminal branch was not observed");
            mvds_end_capture_window();
            SetLastError(outgoing_error); return;
        }
        final_state = 0;
        selector = "LOCATION_ENTER_OUTRO_REQUESTED";
    }
    else if (!completed.projection_site_observed || !completed.projected_x_observed) {
        fail_closed("exhibition route lacks projection call or inline projectedMapX");
        mvds_end_capture_window();
        SetLastError(outgoing_error); return;
    }
    else if (completed.projected_x < 900.0f) {
        if (completed.terminal_branch != EXHIBITION_TERMINAL_LT_900) {
            fail_closed("exhibition projected-X <900 terminal branch differs");
            mvds_end_capture_window();
            SetLastError(outgoing_error); return;
        }
        final_state = 0;
        selector = "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_LT_900";
    }
    else if (completed.projected_x < 2200.0f) {
        if (completed.terminal_branch != EXHIBITION_TERMINAL_LT_2200 ||
            !completed.final_predicate_observed) {
            fail_closed("exhibition 900..2200 terminal predicate is absent");
            mvds_end_capture_window();
            SetLastError(outgoing_error); return;
        }
        final_state = completed.final_mission_complete ? 3 : 0;
        selector = completed.final_mission_complete ?
            "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_EQ_3" :
            "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_NE_3";
    }
    else {
        if (completed.terminal_branch != EXHIBITION_TERMINAL_GTE_2200 ||
            !completed.final_predicate_observed) {
            fail_closed("exhibition >=2200 terminal predicate is absent");
            mvds_end_capture_window();
            SetLastError(outgoing_error); return;
        }
        final_state = completed.final_mission_complete ? 3 : 0;
        selector = completed.final_mission_complete ?
            "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_EQ_3" :
            "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_NE_3";
    }
    emit_location_event(selector,14,artifact,FALSE,final_state,0,0,0,0,outro,
        completed.projected_x_observed,completed.projected_x,"STARTED");
    mvds_end_capture_window();
    SetLastError(outgoing_error);
}

static BOOL mygghanget_absence_is_proven(
    const SelectorFrame *completed, DWORD object
) {
    DWORD queued_root, default_root, active_root;
    queued_root = read_u32(object + 0x8c8);
    default_root = read_u32(object + 0x8d0);
    active_root = read_u32(object + 0x8d4);
    if (completed->observed_route != MVDS_ROUTE_NONE ||
        completed->mygghanget_root_created || completed->root_without_provenance ||
        queued_root != 0 || default_root != 0 || active_root != 0) {
        fail_closed("mygghanget expected-absence interval observed a root or unproven route");
        return FALSE;
    }
    return !g_fatal;
}

static void MVDS_FASTCALL hook_mygghanget_enter(void *self, DWORD ignored) {
    SelectorFrame completed;
    int final_state;
    DWORD incoming_error = GetLastError(), outgoing_error;
    BOOL opened;
    (void)ignored;
    if (!location_target_matches(MVDS_CAPTURE_HOOK_MYGGHANGET_ENTER,22,-1)) {
        SetLastError(incoming_error); g_mygghanget_enter_trampoline(self); return;
    }
    final_state = final_mission_state();
    opened = begin_capture_window_from_target_hook(MVDS_CAPTURE_HOOK_MYGGHANGET_ENTER);
    if (!opened) {
        SetLastError(incoming_error); g_mygghanget_enter_trampoline(self); return;
    }
    begin_selector(SELECTOR_MYGGHANGET,self);
    SetLastError(incoming_error);
    g_mygghanget_enter_trampoline(self);
    outgoing_error = GetLastError();
    completed = g_selector; end_selector();
    if (!mygghanget_absence_is_proven(&completed, (DWORD)(uintptr_t)self)) {
        mvds_end_capture_window();
        SetLastError(outgoing_error); return;
    }
    emit_location_event("LOCATION_ENTER_EXPECTED_UDSP_ABSENCE",22,NULL,FALSE,final_state,
        0,0,0,0,0,FALSE,0.0f,"EXPECTED_ABSENCE");
    mvds_end_capture_window();
    SetLastError(outgoing_error);
}

const MvdsHookSpec *mvds_hook_specs(size_t *count) {
    if (count != NULL) *count = ARRAY_COUNT(g_specs);
    return g_specs;
}

BOOL mvds_arm(const MvdsHost *host, BOOL route_forwarding) {
    size_t index;
    if (host == NULL || host->emit_line == NULL || host->fail_closed == NULL ||
        host->capture_completed == NULL || g_native_process_id == 0 ||
        !bounded_semantic_text(g_capture_session_id,MVDS_CAPTURE_SESSION_CAP) ||
        (g_capture_target.evidence_class == MVDS_EVIDENCE_MISSION_DISPATCH &&
         !route_forwarding) || g_armed || g_capture_window_consumed ||
        !g_capture_target_configured ||
        !valid_sha256_text(MVDS_PRODUCER_BUILD_SHA256) ||
        !semantic_alphabet(host->capture_plan_job_id) ||
        strlen(host->capture_plan_job_id) >= sizeof(g_capture_plan_job_id) ||
        !valid_sha256_text(host->native_slice_sha256) ||
        !valid_sha256_text(host->observer_binary_sha256) ||
        !valid_sha256_text(host->observer_build_receipt_sha256) ||
        strcmp(host->capture_plan_job_id,g_capture_target.job_id) != 0 ||
        strcmp(host->native_slice_sha256,g_capture_target.native_slice_sha256) != 0)
        return FALSE;
    for (index = 0; index < ARRAY_COUNT(g_specs); index++) {
        BOOL required = mvds_hook_required(g_specs[index].id);
        if (required != (*g_specs[index].trampoline_slot != NULL)) return FALSE;
    }
    if (!g_lock_initialized) { InitializeCriticalSection(&g_lock); g_lock_initialized = TRUE; }
    g_host = *host;
    g_route_forwarding = route_forwarding;
    strcpy(g_capture_plan_job_id, host->capture_plan_job_id);
    strcpy(g_native_slice_sha256, host->native_slice_sha256);
    strcpy(g_observer_binary_sha256, host->observer_binary_sha256);
    strcpy(g_observer_build_receipt_sha256, host->observer_build_receipt_sha256);
    g_host.engine_thread_id = 0;
    g_fatal = FALSE;
    g_sequence = 0;
    g_capture_window_active = FALSE;
    g_capture_event_emitted = FALSE;
    g_capture_completion_signalled = FALSE;
    g_completed_generic_readback_valid = FALSE;
    memset(&g_completed_generic_readback,0,sizeof(g_completed_generic_readback));
    g_mission_count = 0;
    g_root_count = 0;
    memset(g_mission_sources,0,sizeof(g_mission_sources));
    memset(&g_action,0,sizeof(g_action));
    memset(&g_selector,0,sizeof(g_selector));
    memset(&g_exhibition_entry,0,sizeof(g_exhibition_entry));
    g_armed = TRUE;
    return TRUE;
}

BOOL mvds_bind_engine_thread(DWORD engine_thread_id) {
    if (!g_armed || g_enabled || g_fatal || engine_thread_id == 0) return FALSE;
    g_host.engine_thread_id = engine_thread_id;
    g_enabled = TRUE;
    return TRUE;
}

BOOL mvds_begin_capture_window(void) {
    char installed_hooks[2048];
    size_t index, used = 0, emitted = 0;
    DWORD installed_mask = mvds_required_hook_mask();
    int written;
    const char *evidence_class;
    if (!g_target_hook_open_authorized || !g_capture_target_configured ||
        !g_armed || !g_enabled || g_fatal || g_capture_window_active ||
        g_capture_window_consumed || g_host.engine_thread_id == 0 ||
        GetCurrentThreadId() != g_host.engine_thread_id) return FALSE;
    evidence_class = g_capture_target.evidence_class == MVDS_EVIDENCE_MISSION_DISPATCH ?
        "MISSION_DISPATCH" : "LOCATION_POLICY";
    g_capture_window_consumed = TRUE;
    g_capture_window_active = TRUE;
    g_capture_event_emitted = FALSE;
    installed_hooks[used++] = '[';
    for (index = 0; index < ARRAY_COUNT(g_specs); index++) {
        if (!mvds_hook_required(g_specs[index].id)) continue;
        if (!semantic_alphabet(g_specs[index].name)) {
            fail_closed("hook name is not ASCII-safe");
            return FALSE;
        }
        written = snprintf(installed_hooks + used, sizeof(installed_hooks) - used,
            "%s\"%s\"", emitted == 0 ? "" : ",", g_specs[index].name);
        if (written < 0 || (size_t)written >= sizeof(installed_hooks) - used) {
            fail_closed("installed hook capability list overflow");
            return FALSE;
        }
        used += (size_t)written;
        ++emitted;
    }
    if (used + 2 > sizeof(installed_hooks)) {
        fail_closed("installed hook capability list overflow");
        return FALSE;
    }
    installed_hooks[used++] = ']';
    installed_hooks[used] = '\0';
    if (!emitf("{\"schema\":1,\"protocol\":\"%s\",\"record\":\"CAPABILITY\","
        "\"executableSha256\":\"%s\",\"runtimeCapture\":true,\"routeForwarding\":%s,\"engineThread\":%lu,"
        "\"nativeProcessId\":%lu,\"captureSessionId\":\"%s\","
        "\"producerBuildSha256\":\"%s\","
        "\"capturePlanJobId\":\"%s\",\"nativeSliceSha256\":\"%s\","
        "\"targetSha256\":\"%s\",\"jobSha256\":\"%s\","
        "\"claimId\":\"%s\",\"claimSha256\":\"%s\","
        "\"subjectSha256\":\"%s\",\"expectationSha256\":\"%s\","
        "\"scenarioSha256\":\"%s\",\"capturePlanSha256\":\"%s\","
        "\"planManifestSha256\":\"%s\",\"evidenceClass\":\"%s\","
        "\"observerBinarySha256\":\"%s\",\"observerBuildReceiptSha256\":\"%s\","
        "\"installedHookCount\":%lu,\"installedHookMask\":\"0x%08lx\",\"installedHooks\":%s,"
        "\"forwardedRouteHooks\":%s,"
        "\"capabilities\":{\"triggerIdentity\":true,\"selectorPredicates\":true,\"route\":%s,\"artifact\":true,\"stateBefore\":true,\"stateAfter\":true}}",
        MVDS_PROTOCOL,MVDS_EXECUTABLE_SHA256,
        g_route_forwarding ? "true" : "false",
        (unsigned long)g_host.engine_thread_id,
        (unsigned long)g_native_process_id,g_capture_session_id,
        MVDS_PRODUCER_BUILD_SHA256,
        g_capture_plan_job_id,g_native_slice_sha256,
        g_capture_target.target_sha256,g_capture_target.job_sha256,
        g_capture_target.claim_id,g_capture_target.claim_sha256,
        g_capture_target.subject_sha256,g_capture_target.expectation_sha256,
        g_capture_target.scenario_sha256,g_capture_target.capture_plan_sha256,
        g_capture_target.plan_manifest_sha256,evidence_class,
        g_observer_binary_sha256,g_observer_build_receipt_sha256,
        (unsigned long)emitted,(unsigned long)installed_mask,installed_hooks,
        g_route_forwarding ?
            "[\"SCENE_DISPATCH_GROUND\",\"SCENE_DISPATCH_BARN\",\"SCENE_DISPATCH_FLIGHT\"]" :
            "[]",
        g_route_forwarding ? "true" : "false")) {
        g_capture_window_active = FALSE;
        return FALSE;
    }
    return TRUE;
}

BOOL mvds_end_capture_window(void) {
    if (!g_armed || !g_enabled || g_fatal || !g_capture_window_consumed ||
        GetCurrentThreadId() != g_host.engine_thread_id) return FALSE;
    if (g_capture_window_active || !g_capture_event_emitted) {
        g_capture_window_active = FALSE;
        fail_closed("capture job ended without exactly one semantic EVENT");
        return FALSE;
    }
    if (g_capture_completion_signalled ||
        !g_host.capture_completed(g_native_process_id,g_capture_session_id,
            g_host.context)) {
        fail_closed("capture completion identity was not durably signalled");
        return FALSE;
    }
    g_capture_completion_signalled = TRUE;
    return TRUE;
}

BOOL mvds_enable(const MvdsHost *host, BOOL route_forwarding) {
    MvdsHost armed;
    if (host == NULL || host->engine_thread_id == 0) return FALSE;
    armed = *host;
    armed.engine_thread_id = 0;
    return mvds_arm(&armed,route_forwarding) &&
        mvds_bind_engine_thread(host->engine_thread_id);
}

void mvds_disable(void) {
    g_enabled = FALSE;
    g_capture_window_active = FALSE;
    g_armed = FALSE;
    g_route_forwarding = FALSE;
    g_target_hook_open_authorized = FALSE;
    g_capture_target_configured = FALSE;
    memset(&g_capture_target,0,sizeof(g_capture_target));
    g_completed_generic_readback_valid = FALSE;
    memset(&g_completed_generic_readback,0,sizeof(g_completed_generic_readback));
    memset(&g_host,0,sizeof(g_host));
    memset(g_capture_plan_job_id,0,sizeof(g_capture_plan_job_id));
    memset(g_native_slice_sha256,0,sizeof(g_native_slice_sha256));
    memset(g_observer_binary_sha256,0,sizeof(g_observer_binary_sha256));
    memset(g_observer_build_receipt_sha256,0,sizeof(g_observer_build_receipt_sha256));
}

void mvds_observe_route(MvdsRoute route, DWORD object, DWORD root) {
    char artifact[ARTIFACT_CAP];
    DWORD last_error = GetLastError();
    if (!on_engine_thread()) { SetLastError(last_error); return; }
    if (g_action.active) {
        if (g_action.observed_route != MVDS_ROUTE_NONE) {
            fail_closed("duplicate mission route observation");
        } else if (g_action.expected_route != route ||
            g_action.expected_object == 0 || g_action.expected_object != object) {
            fail_closed("mission route observation object or route differs");
        } else {
        g_action.observed_route = route;
        g_action.observed_root = root;
        }
    }
    if (g_selector.kind != SELECTOR_NONE) {
        if (g_selector.observed_route != MVDS_ROUTE_NONE) {
            fail_closed("duplicate selector route observation");
        } else if (g_selector.object == 0 || g_selector.object != object) {
            fail_closed("selector route observation object differs");
        } else {
            g_selector.observed_route = route;
            g_selector.observed_root = root;
            if (!root_artifact(root,artifact,sizeof(artifact)))
                g_selector.root_without_provenance = TRUE;
        }
    }
    SetLastError(last_error);
}
