#!/usr/bin/env python3
import copy
import json
import unittest
from pathlib import Path

from tools.miel_vliegt import native_udsp_fact_protocol as facts


ROOT = Path(__file__).resolve().parents[2]
EXECUTABLE = json.loads(
    (ROOT / "content/miel_vliegt/executable_udsp_scene_scripts.json").read_text()
)
NATIVE_COMMANDS = json.loads(
    (ROOT / "content/miel_vliegt/native_udsp_scene_commands.json").read_text()
)
MODIFIER_IDS = NATIVE_COMMANDS["engine"]["modifiers"]
SCRIPTS = {script["path"]: script for script in EXECUTABLE["scripts"]}


def add(records, event, thread_handle, **fields):
    records.append({
        "sequence": len(records), "event": event,
        "threadHandle": thread_handle, **fields,
    })


def allocate_thread(records, next_handle):
    thread_handle = next_handle
    add(records, "THREAD_ATTACH", thread_handle)
    return thread_handle, next_handle + 1


def source_bytes(path):
    # The pinned corpus is ASCII, but the native producer reports the exact
    # Windows path bytes. Normalization belongs to the validator.
    return path.replace("/", "\\").encode("ascii").hex()


def add_parse(
    records, path, next_handle, thread_handle, *,
    cause_call_handle=None, cause_dispatch_handle=None,
    parse_interleave_failed_parse=None,
):
    script = SCRIPTS[path]
    parse_handle = next_handle
    next_handle += 1
    add(
        records, "PARSE_BEGIN", thread_handle,
        parseHandle=parse_handle, sourcePathBytesHex=source_bytes(path),
        causeCallHandle=cause_call_handle,
        causeDispatchHandle=cause_dispatch_handle,
    )
    if parse_interleave_failed_parse is not None:
        _, next_handle = add_failed_parse(
            records, parse_interleave_failed_parse,
            next_handle, thread_handle,
        )
    handles = {}

    def visit(node, parent_handle, ordinal, path_tuple):
        nonlocal next_handle
        handle = next_handle
        next_handle += 1
        handles[path_tuple] = handle
        if "command" in node:
            command = script["commands"][node["command"]]
            add(
                records, "GRAPH_NODE", thread_handle,
                parseHandle=parse_handle, nodeHandle=handle,
                parentHandle=parent_handle, childOrdinal=ordinal, nodeType=6,
                commandId=command["nativeOpcode"],
                modifierId=MODIFIER_IDS[command["modifier"] or "NONE"],
            )
        else:
            add(
                records, "GRAPH_NODE", thread_handle,
                parseHandle=parse_handle, nodeHandle=handle,
                parentHandle=parent_handle, childOrdinal=ordinal, nodeType=4,
                repeat=node["repeat"],
            )
            for child_ordinal, child in enumerate(node["children"]):
                visit(child, handle, child_ordinal, path_tuple + (child_ordinal,))
        return handle

    visit(script["structure"], None, 0, ())
    add(
        records, "PARSE_END", thread_handle,
        parseHandle=parse_handle, success=True,
        returnedNodeHandle=handles[()], graphCount=len(handles),
    )
    return script, handles, parse_handle, next_handle


def add_failed_parse(records, path, next_handle, thread_handle):
    parse_handle = next_handle
    next_handle += 1
    add(
        records, "PARSE_BEGIN", thread_handle,
        parseHandle=parse_handle, sourcePathBytesHex=source_bytes(path),
        causeCallHandle=None, causeDispatchHandle=None,
    )
    add(
        records, "PARSE_END", thread_handle,
        parseHandle=parse_handle, success=False,
        returnedNodeHandle=None, graphCount=0,
    )
    return parse_handle, next_handle


def find_command(script, handles, command_id, *, modifier=None):
    def visit(node, path):
        if "command" in node:
            command = script["commands"][node["command"]]
            if command["nativeOpcode"] == command_id \
                    and (modifier is None or command["modifier"] == modifier):
                return handles[path]
            return None
        for ordinal, child in enumerate(node["children"]):
            found = visit(child, path + (ordinal,))
            if found is not None:
                return found
        return None

    result = visit(script["structure"], ())
    if result is None:
        raise AssertionError(f"fixture has no command {command_id}")
    return result


def document(records):
    return {
        "schema": 2,
        "protocol": facts.PROTOCOL,
        "producer": facts.PRODUCER,
        "records": records,
    }


def add_root_start(
    records, next_handle, thread_handle, parse_handle, root_node,
    current_node, *, cause_call=None, cause_dispatch=None,
    running_before=False, complete_before=False,
    reset_interleave_failed_parse=None,
    start_interleave_failed_parse=None,
):
    root_handle = next_handle
    next_handle += 1
    add(
        records, "ROOT_START_BEGIN", thread_handle,
        rootHandle=root_handle, parseHandle=parse_handle,
        rootNodeHandle=root_node, causeCallHandle=cause_call,
        causeDispatchHandle=cause_dispatch, runningBefore=running_before,
        completeBefore=complete_before,
    )
    if start_interleave_failed_parse is not None:
        _, next_handle = add_failed_parse(
            records, start_interleave_failed_parse,
            next_handle, thread_handle,
        )
    graph = {
        row["nodeHandle"]: row for row in records
        if row["event"] == "GRAPH_NODE" and row["parseHandle"] == parse_handle
    }

    def children(node_handle):
        return sorted(
            (row for row in graph.values()
             if row["parentHandle"] == node_handle),
            key=lambda row: row["childOrdinal"],
        )

    def latest_reset_state(node_handle):
        for row in reversed(records):
            if row["event"] == "COMPOSITE_RESET_END" \
                    and row["nodeHandle"] == node_handle:
                return row["completeAfter"], row["currentNodeHandleAfter"]
        return False, None

    def emit_reset(node_handle):
        nonlocal next_handle
        reset_handle = next_handle
        next_handle += 1
        complete, current = latest_reset_state(node_handle)
        if node_handle == root_node:
            complete = complete_before
        direct_children = children(node_handle)
        first_child = direct_children[0]["nodeHandle"] if direct_children else None
        add(
            records, "COMPOSITE_RESET_BEGIN", thread_handle,
            resetHandle=reset_handle, rootHandle=root_handle,
            nodeHandle=node_handle, contextKind="ROOT_START",
            contextHandle=root_handle, dispatchHandle=None,
            completeBefore=complete, currentNodeHandleBefore=current,
        )
        if node_handle == root_node and reset_interleave_failed_parse is not None:
            _, next_handle = add_failed_parse(
                records, reset_interleave_failed_parse,
                next_handle, thread_handle,
            )
        for child in direct_children:
            if child["nodeType"] == 4:
                emit_reset(child["nodeHandle"])
        add(
            records, "COMPOSITE_RESET_END", thread_handle,
            resetHandle=reset_handle, rootHandle=root_handle,
            nodeHandle=node_handle, completeAfter=False,
            currentNodeHandleAfter=first_child,
        )

    emit_reset(root_node)
    add(
        records, "ROOT_START_END", thread_handle,
        rootHandle=root_handle, parseHandle=parse_handle,
        rootNodeHandle=root_node, runningAfter=True, completeAfter=False,
    )
    return root_handle, next_handle


def valid_document(
    *, callback=True, callback_thread=False, rearm_started=False,
    other_thread_parse=False, update_interleave_failed_parse=False,
    repeat_wait_random=False, rng_on_wait_redispatch=False,
):
    """Scheduler-shaped atle trace covering animation, callback, and wait-random."""
    records = []
    thread, next_handle = allocate_thread(records, 1)
    other_thread = None
    if callback_thread or other_thread_parse:
        other_thread, next_handle = allocate_thread(records, next_handle)
    script, handles, parse_handle, next_handle = add_parse(
        records, "data/Scripts/Characters/atle/stand.def", next_handle, thread,
    )
    root_node = handles[()]
    root_handle, next_handle = add_root_start(
        records, next_handle, thread, parse_handle, root_node, None,
    )
    callback_arm = None
    callback_node = None
    command_state = {
        handle: {"complete": False, "started": False}
        for path, handle in handles.items()
        if "command" in _node_at_path(script["structure"], path)
    }

    updates = [
        ((0, 0), (1, 0), (2, 0), (3, 0)),
        ((0, 0), (3, 1)) if callback and not callback_thread else ((3, 1),),
    ]
    if repeat_wait_random:
        updates.append(((3, 1),))
    for ordinal, paths in enumerate(updates):
        call_handle = next_handle
        next_handle += 1
        add(
            records, "ROOT_UPDATE_BEGIN", thread,
            callHandle=call_handle, rootHandle=root_handle,
            updateOrdinal=ordinal, deltaF32Bits="3e800000",
            runningBefore=True, completeBefore=False,
        )
        if update_interleave_failed_parse and ordinal == 0:
            _, next_handle = add_failed_parse(
                records, "data/Scripts/Characters/brejton/stand.def",
                next_handle, thread,
            )
        for path in paths:
            command_node = handles[path]
            command = script["commands"][_node_at_path(
                script["structure"], path,
            )["command"]]
            state = command_state[command_node]
            dispatch_handle = next_handle
            next_handle += 1
            add(
                records, "DISPATCH_BEGIN", thread,
                callHandle=call_handle, dispatchHandle=dispatch_handle,
                rootHandle=root_handle, nodeHandle=command_node,
                commandId=command["nativeOpcode"], deltaF32Bits="3e800000",
                completeBefore=state["complete"],
                startedBefore=state["started"],
            )
            if callback and callback_arm is None:
                callback_arm = next_handle
                next_handle += 1
                callback_node = command_node
                add(
                    records, "CALLBACK_ARM", thread,
                    armHandle=callback_arm, parseHandle=parse_handle,
                    nodeHandle=command_node, rootHandle=root_handle,
                    callHandle=call_handle, dispatchHandle=dispatch_handle,
                    modifierId=MODIFIER_IDS["WAIT"],
                )
            if rearm_started and ordinal == 1 and path == (0, 0):
                add(
                    records, "CALLBACK_ARM", thread,
                    armHandle=next_handle, parseHandle=parse_handle,
                    nodeHandle=command_node, rootHandle=root_handle,
                    callHandle=call_handle, dispatchHandle=dispatch_handle,
                    modifierId=MODIFIER_IDS["WAIT"],
                )
            if command["nativeOpcode"] == 15 and (
                not state["started"] or rng_on_wait_redispatch
            ):
                add(
                    records, "RNG_DRAW", thread,
                    callHandle=call_handle, dispatchHandle=dispatch_handle,
                    rootHandle=root_handle, nodeHandle=command_node,
                    drawOrdinal=0, rawRandU15=9362,
                )
            complete_after = not (
                callback and ordinal == 0 and path == (0, 0)
            )
            if repeat_wait_random and ordinal == 1 and path == (3, 1):
                complete_after = False
            if callback and callback_thread and ordinal == 0 and path == (0, 0):
                add(
                    records, "CALLBACK", other_thread,
                    armHandle=callback_arm, parseHandle=parse_handle,
                    nodeHandle=callback_node, rootHandle=root_handle,
                    callHandle=None, dispatchHandle=None, callbackCode=1,
                    completeBefore=False, completeAfter=True, returnU32=1,
                )
                complete_after = True
            state.update(complete=complete_after, started=True)
            add(
                records, "DISPATCH_END", thread,
                callHandle=call_handle, dispatchHandle=dispatch_handle,
                rootHandle=root_handle, nodeHandle=command_node,
                commandId=command["nativeOpcode"],
                completeAfter=complete_after, startedAfter=True,
                exitSiteCode=0,
            )
            if other_thread_parse and ordinal == 0 and path == (0, 0):
                _, next_handle = add_failed_parse(
                    records, "data/Scripts/Characters/brejton/stand.def",
                    next_handle, other_thread,
                )
        add(
            records, "ROOT_UPDATE_END", thread,
            callHandle=call_handle, rootHandle=root_handle,
            runningAfter=True, completeAfter=False,
        )
        if callback and not callback_thread and ordinal == 0:
            add(
                records, "CALLBACK", thread,
                armHandle=callback_arm, parseHandle=parse_handle,
                nodeHandle=callback_node, rootHandle=root_handle,
                callHandle=None, dispatchHandle=None, callbackCode=1,
                completeBefore=False, completeAfter=True, returnU32=1,
            )
            command_state[callback_node]["complete"] = True
    return document(records)


def allfinished_document(
    *, stop_after_update=2, nested_parse=False, preparse_for_nested_start=False,
    duplicate_nested_start=False, restart_started_script=False,
):
    records = []
    thread, next_handle = allocate_thread(records, 1)
    script, handles, parse_handle, next_handle = add_parse(
        records, "data/Scripts/Locations/atle_artillerist/allfinished.def",
        next_handle, thread,
    )
    nested = None
    if preparse_for_nested_start:
        _, nested_handles, nested_parse_handle, next_handle = add_parse(
            records, "data/Scripts/Characters/brejton/stand.def",
            next_handle, thread,
        )
        nested = (nested_handles, nested_parse_handle)
    root_handle, next_handle = add_root_start(
        records, next_handle, thread, parse_handle, handles[()], None,
    )
    command_state = {
        handle: {"complete": False, "started": False}
        for path, handle in handles.items()
        if "command" in _node_at_path(script["structure"], path)
    }
    paths_by_update = [
        [(0, 0), (1, 0), (2, 0)],
        [(0, 1), (1, 1), (2, 1)],
        [(3,)], [(4,)], [(5, 0), (6, 0)], [(7,)], [(8,)], [(9,)],
    ]
    injected = False
    for ordinal, paths in enumerate(paths_by_update[:stop_after_update + 1]):
        if restart_started_script and ordinal == 4:
            paths = [(4,)]
        call_handle = next_handle
        next_handle += 1
        add(
            records, "ROOT_UPDATE_BEGIN", thread,
            callHandle=call_handle, rootHandle=root_handle,
            updateOrdinal=ordinal, deltaF32Bits="3e800000",
            runningBefore=True, completeBefore=False,
        )
        for path in paths:
            node_handle = handles[path]
            command = script["commands"][_node_at_path(
                script["structure"], path,
            )["command"]]
            state = command_state[node_handle]
            dispatch_handle = next_handle
            next_handle += 1
            add(
                records, "DISPATCH_BEGIN", thread,
                callHandle=call_handle, dispatchHandle=dispatch_handle,
                rootHandle=root_handle, nodeHandle=node_handle,
                commandId=command["nativeOpcode"],
                deltaF32Bits="3e800000",
                completeBefore=state["complete"],
                startedBefore=state["started"],
            )
            if command["nativeOpcode"] in {6, 14} \
                    or command["modifier"] == "WAIT_RANDOM":
                add(
                    records, "RNG_DRAW", thread,
                    callHandle=call_handle, dispatchHandle=dispatch_handle,
                    rootHandle=root_handle, nodeHandle=node_handle,
                    drawOrdinal=0, rawRandU15=9362,
                )
            if command["nativeOpcode"] == 1:
                if not injected and nested_parse:
                    add_parse(
                        records, "data/Scripts/Characters/brejton/stand.def",
                        next_handle, thread, cause_call_handle=call_handle,
                        cause_dispatch_handle=dispatch_handle,
                    )
                    next_handle = max(
                        value for row in records for key, value in row.items()
                        if key.endswith("Handle") and type(value) is int
                    ) + 1
                    injected = True
                elif not injected and nested is not None and (
                    not restart_started_script or path == (4,)
                ):
                    nested_handles, nested_parse_handle = nested
                    _, next_handle = add_root_start(
                        records, next_handle, thread, nested_parse_handle,
                        nested_handles[()], None, cause_call=call_handle,
                        cause_dispatch=dispatch_handle,
                    )
                    if duplicate_nested_start:
                        _, next_handle = add_root_start(
                            records, next_handle, thread, nested_parse_handle,
                            nested_handles[()], None, cause_call=call_handle,
                            cause_dispatch=dispatch_handle,
                        )
                    injected = True
                elif injected and nested is not None and restart_started_script \
                        and path == (4,) and state["started"]:
                    nested_handles, nested_parse_handle = nested
                    _, next_handle = add_root_start(
                        records, next_handle, thread, nested_parse_handle,
                        nested_handles[()], None, cause_call=call_handle,
                        cause_dispatch=dispatch_handle,
                    )
            complete_after = not (
                restart_started_script and path == (4,)
            )
            state.update(complete=complete_after, started=True)
            add(
                records, "DISPATCH_END", thread,
                callHandle=call_handle, dispatchHandle=dispatch_handle,
                rootHandle=root_handle, nodeHandle=node_handle,
                commandId=command["nativeOpcode"],
                completeAfter=complete_after,
                startedAfter=True, exitSiteCode=0,
            )
        is_final = ordinal == 7
        add(
            records, "ROOT_UPDATE_END", thread,
            callHandle=call_handle, rootHandle=root_handle,
            runningAfter=not is_final, completeAfter=is_final,
        )
    return document(records)


def native_repeat_reset_document():
    """A native scheduler-shaped trace that reaches atle's repeat reset."""
    records = []
    thread, next_handle = allocate_thread(records, 1)
    script, handles, parse_handle, next_handle = add_parse(
        records, "data/Scripts/Characters/atle/stand.def",
        next_handle, thread,
    )
    root_node = handles[()]
    root_handle, next_handle = add_root_start(
        records, next_handle, thread, parse_handle, root_node, None,
    )
    command_state = {
        handle: {"complete": False, "started": False}
        for path, handle in handles.items()
        if "command" in _node_at_path(script["structure"], path)
    }

    for ordinal in range(7):
        call_handle = next_handle
        next_handle += 1
        add(
            records, "ROOT_UPDATE_BEGIN", thread,
            callHandle=call_handle, rootHandle=root_handle,
            updateOrdinal=ordinal, deltaF32Bits="3e800000",
            runningBefore=True, completeBefore=False,
        )
        paths = [(3, ordinal)]
        if ordinal == 0:
            paths = [(0, 0), (1, 0), (2, 0), (3, 0)]
        for path in paths:
            node_handle = handles[path]
            command = script["commands"][_node_at_path(
                script["structure"], path,
            )["command"]]
            dispatch_handle = next_handle
            next_handle += 1
            state = command_state[node_handle]
            add(
                records, "DISPATCH_BEGIN", thread,
                callHandle=call_handle, dispatchHandle=dispatch_handle,
                rootHandle=root_handle, nodeHandle=node_handle,
                commandId=command["nativeOpcode"],
                deltaF32Bits="3e800000",
                completeBefore=state["complete"],
                startedBefore=state["started"],
            )
            if command["nativeOpcode"] == 15:
                add(
                    records, "RNG_DRAW", thread,
                    callHandle=call_handle, dispatchHandle=dispatch_handle,
                    rootHandle=root_handle, nodeHandle=node_handle,
                    drawOrdinal=0, rawRandU15=9362,
                )
            state.update(complete=True, started=True)
            add(
                records, "DISPATCH_END", thread,
                callHandle=call_handle, dispatchHandle=dispatch_handle,
                rootHandle=root_handle, nodeHandle=node_handle,
                commandId=command["nativeOpcode"],
                completeAfter=True, startedAfter=True, exitSiteCode=0,
            )
        if ordinal == 6:
            repeat_node = handles[(3,)]
            reset_handle = next_handle
            next_handle += 1
            add(
                records, "COMPOSITE_RESET_BEGIN", thread,
                resetHandle=reset_handle, rootHandle=root_handle,
                nodeHandle=repeat_node, contextKind="ROOT_UPDATE",
                contextHandle=call_handle, dispatchHandle=None,
                completeBefore=True, currentNodeHandleBefore=None,
            )
            add(
                records, "COMPOSITE_RESET_END", thread,
                resetHandle=reset_handle, rootHandle=root_handle,
                nodeHandle=repeat_node, completeAfter=False,
                currentNodeHandleAfter=handles[(3, 0)],
            )
        add(
            records, "ROOT_UPDATE_END", thread,
            callHandle=call_handle, rootHandle=root_handle,
            runningAfter=True, completeAfter=False,
        )
    return document(records)


def _node_at_path(node, path):
    for ordinal in path:
        node = node["children"][ordinal]
    return node


def renumber(records):
    for sequence, row in enumerate(records):
        row["sequence"] = sequence


def reorder_graph_breadth_first(trace):
    """Keep observer handles contiguous while forging breadth-first parse order."""
    graph_indices = [
        index for index, row in enumerate(trace["records"])
        if row["event"] == "GRAPH_NODE"
    ]
    original = [copy.deepcopy(trace["records"][index]) for index in graph_indices]
    by_handle = {row["nodeHandle"]: row for row in original}
    paths = {}

    def path_for(row):
        handle = row["nodeHandle"]
        if handle in paths:
            return paths[handle]
        parent = row["parentHandle"]
        path = () if parent is None else path_for(by_handle[parent]) + (
            row["childOrdinal"],
        )
        paths[handle] = path
        return path

    breadth_first = sorted(original, key=lambda row: (
        len(path_for(row)), path_for(row),
    ))
    handle_map = {
        row["nodeHandle"]: original[index]["nodeHandle"]
        for index, row in enumerate(breadth_first)
    }
    for index, row in zip(graph_indices, breadth_first):
        trace["records"][index] = row
    reference_fields = {
        "nodeHandle", "parentHandle", "returnedNodeHandle", "rootNodeHandle",
        "currentNodeHandleBefore", "currentNodeHandleAfter",
    }
    for row in trace["records"]:
        for field in reference_fields:
            value = row.get(field)
            if value in handle_map:
                row[field] = handle_map[value]
    renumber(trace["records"])


class NativeUdspFactProtocolTests(unittest.TestCase):
    def assert_rejected(self, value, fragment=None):
        with self.assertRaises(facts.NativeUdspFactError) as raised:
            facts.validate_native_udsp_facts(value)
        if fragment:
            self.assertIn(fragment, str(raised.exception))

    def test_validates_minimal_v2_facts_and_derives_only_structural_capabilities(self):
        result = facts.validate_native_udsp_facts(valid_document())
        self.assertEqual(result["protocol"], facts.VALIDATED_PROTOCOL)
        self.assertEqual(result["supportStatus"], facts.SUPPORT_STATUS)
        self.assertEqual(result["bindings"][0]["sourcePath"],
                         "data/Scripts/Characters/atle/stand.def")
        self.assertEqual(result["bindings"][0]["sourceSha256"],
                         SCRIPTS["data/Scripts/Characters/atle/stand.def"]["sourceSha256"])
        self.assertEqual(result["capabilities"]["observerThreadHandleCount"], 1)
        self.assertTrue(result["capabilities"]["parseGraph"])
        self.assertTrue(result["capabilities"]["rootStartLifecycle"])
        self.assertTrue(result["capabilities"]["compositeResetLifecycle"])
        self.assertTrue(result["capabilities"]["callback"])
        self.assertEqual(result["capabilities"]["coveredCommandIds"], [3, 15])
        self.assertEqual(result["capabilities"]["effects"], {
            "supported": False, "status": "UNSUPPORTED_NO_NATIVE_EFFECT_ABI",
        })

    def test_thread_attach_scopes_active_context_and_cross_thread_callback(self):
        trace = valid_document(callback_thread=True)
        result = facts.validate_native_udsp_facts(trace)
        self.assertEqual(result["capabilities"]["observerThreadHandleCount"], 2)

        bad = copy.deepcopy(trace)
        callback = next(row for row in bad["records"]
                        if row["event"] == "CALLBACK")
        callback["callHandle"] = next(
            row["callHandle"] for row in bad["records"]
            if row["event"] == "ROOT_UPDATE_BEGIN"
        )
        self.assert_rejected(bad, "callback call context")

    def test_other_thread_can_parse_while_first_thread_update_is_open(self):
        trace = valid_document(callback=False, other_thread_parse=True)
        result = facts.validate_native_udsp_facts(trace)
        self.assertEqual(result["capabilities"]["observerThreadHandleCount"], 2)
        self.assertFalse(result["capabilities"]["parseGraph"])

    def test_thread_detach_is_not_an_observable_wire_event(self):
        trace = valid_document()
        add(trace["records"], "THREAD_DETACH", 1)
        self.assert_rejected(trace, "unknown native fact event")

    def test_unused_observer_thread_handles_are_rejected(self):
        trace = valid_document()
        next_handle = max(
            value for row in trace["records"] for key, value in row.items()
            if key.endswith("Handle") and type(value) is int
        ) + 1
        add(trace["records"], "THREAD_ATTACH", next_handle)
        self.assert_rejected(trace, "no native fact events")

    def test_source_path_is_derived_from_exact_raw_bytes_and_hash_is_not_raw(self):
        facts.validate_native_udsp_facts(valid_document())
        trace = valid_document()
        begin = next(row for row in trace["records"] if row["event"] == "PARSE_BEGIN")
        begin["sourceSha256"] = SCRIPTS[
            "data/Scripts/Characters/atle/stand.def"
        ]["sourceSha256"]
        self.assert_rejected(trace, "record shape")
        trace = valid_document()
        begin = next(row for row in trace["records"] if row["event"] == "PARSE_BEGIN")
        begin["sourcePathBytesHex"] = b"data\\Scripts\\nope.def".hex()
        self.assert_rejected(trace, "not pinned")

    def test_failed_parse_end_is_structural_and_cannot_start_a_root(self):
        records = []
        thread, next_handle = allocate_thread(records, 1)
        parse_handle, next_handle = add_failed_parse(
            records, "data/Scripts/Characters/atle/stand.def",
            next_handle, thread,
        )
        result = facts.validate_native_udsp_facts(document(records))
        self.assertFalse(result["capabilities"]["parseGraph"])
        self.assertFalse(result["bindings"][0]["parseSucceeded"])
        add(
            records, "ROOT_START_BEGIN", thread,
            rootHandle=next_handle, parseHandle=parse_handle,
            rootNodeHandle=next_handle + 1, causeCallHandle=None,
            causeDispatchHandle=None, runningBefore=False,
            completeBefore=False,
        )
        self.assert_rejected(document(records), "failed parse")

    def test_root_start_cause_is_independent_of_earlier_parse_cause(self):
        trace = allfinished_document(
            stop_after_update=1, preparse_for_nested_start=True,
        )
        facts.validate_native_udsp_facts(trace)

    def test_udsp_dispatch_cannot_invoke_the_native_parser(self):
        trace = allfinished_document(stop_after_update=1, nested_parse=True)
        self.assert_rejected(trace, "parser is not callable")

    def test_play_character_script_starts_at_most_one_root(self):
        trace = allfinished_document(
            stop_after_update=1, preparse_for_nested_start=True,
            duplicate_nested_start=True,
        )
        self.assert_rejected(trace, "started multiple roots")

        trace = allfinished_document(
            stop_after_update=4, preparse_for_nested_start=True,
            restart_started_script=True,
        )
        self.assert_rejected(trace, "started PLAY_CHARACTER_SCRIPT")

    def test_start_and_reset_are_strict_begin_end_lifecycles(self):
        for event in ("ROOT_START_END", "COMPOSITE_RESET_END"):
            with self.subTest(event=event):
                trace = valid_document()
                trace["records"] = [row for row in trace["records"]
                                    if row["event"] != event]
                renumber(trace["records"])
                self.assert_rejected(trace)
        trace = valid_document()
        reset = next(row for row in trace["records"]
                     if row["event"] == "COMPOSITE_RESET_BEGIN")
        reset["contextKind"] = "ROOT_UPDATE"
        self.assert_rejected(trace, "reset update context")

    def test_recursive_reset_tree_order_and_exact_state_are_enforced(self):
        trace = valid_document(callback=False)
        composite_nodes = sum(
            row["event"] == "GRAPH_NODE" and row["nodeType"] == 4
            for row in trace["records"]
        )
        self.assertEqual(
            sum(row["event"] == "COMPOSITE_RESET_BEGIN"
                for row in trace["records"]),
            composite_nodes,
        )

        bad = copy.deepcopy(trace)
        root_begin = next(i for i, row in enumerate(bad["records"])
                          if row["event"] == "COMPOSITE_RESET_BEGIN")
        root_handle = bad["records"][root_begin]["resetHandle"]
        root_end = next(i for i, row in enumerate(bad["records"])
                        if row["event"] == "COMPOSITE_RESET_END"
                        and row["resetHandle"] == root_handle)
        row = bad["records"].pop(root_end)
        bad["records"].insert(root_begin + 1, row)
        renumber(bad["records"])
        self.assert_rejected(bad, "recursive composite reset tree")

        bad = copy.deepcopy(trace)
        begin = next(row for row in bad["records"]
                     if row["event"] == "COMPOSITE_RESET_BEGIN")
        begin["completeBefore"] = True
        self.assert_rejected(bad, "completion prestate")

        bad = copy.deepcopy(trace)
        root_start = next(row for row in bad["records"]
                          if row["event"] == "ROOT_START_BEGIN")
        end = next(row for row in bad["records"]
                   if row["event"] == "COMPOSITE_RESET_END"
                   and row["nodeHandle"] == root_start["rootNodeHandle"])
        root_children = [
            row for row in bad["records"]
            if row["event"] == "GRAPH_NODE"
            and row["parentHandle"] == root_start["rootNodeHandle"]
        ]
        self.assertGreaterEqual(len(root_children), 2)
        end["currentNodeHandleAfter"] = root_children[1]["nodeHandle"]
        self.assert_rejected(bad, "first native child")

    def test_recursive_reset_rejects_same_thread_side_event_interleaving(self):
        records = []
        thread, next_handle = allocate_thread(records, 1)
        _, handles, parse_handle, next_handle = add_parse(
            records, "data/Scripts/Characters/atle/stand.def",
            next_handle, thread,
        )
        add_root_start(
            records, next_handle, thread, parse_handle, handles[()], None,
            reset_interleave_failed_parse=(
                "data/Scripts/Characters/brejton/stand.def"
            ),
        )
        self.assert_rejected(
            document(records), "only exact recursive reset events",
        )

    def test_synchronous_lifecycle_stack_rejects_parser_interleavings(self):
        records = []
        thread, next_handle = allocate_thread(records, 1)
        add_parse(
            records, "data/Scripts/Characters/atle/stand.def",
            next_handle, thread,
            parse_interleave_failed_parse=(
                "data/Scripts/Characters/brejton/stand.def"
            ),
        )
        self.assert_rejected(
            document(records), "open parser permits only",
        )

        records = []
        thread, next_handle = allocate_thread(records, 1)
        _, handles, parse_handle, next_handle = add_parse(
            records, "data/Scripts/Characters/atle/stand.def",
            next_handle, thread,
        )
        add_root_start(
            records, next_handle, thread, parse_handle, handles[()], None,
            start_interleave_failed_parse=(
                "data/Scripts/Characters/brejton/stand.def"
            ),
        )
        self.assert_rejected(
            document(records), "open root start permits only",
        )

        self.assert_rejected(
            valid_document(
                callback=False, update_interleave_failed_parse=True,
            ),
            "native scheduler lifecycle",
        )

    def test_arbitrary_update_reset_is_not_scheduler_authorized(self):
        trace = valid_document(callback=False)
        records = trace["records"]
        update_end = next(i for i, row in enumerate(records)
                          if row["event"] == "ROOT_UPDATE_END")
        call = next(row["callHandle"] for row in records
                    if row["event"] == "ROOT_UPDATE_BEGIN")
        root = next(row["rootHandle"] for row in records
                    if row["event"] == "ROOT_START_BEGIN")
        root_node = next(row["rootNodeHandle"] for row in records
                         if row["event"] == "ROOT_START_BEGIN")
        leaf_reset = next(
            row for row in records
            if row["event"] == "COMPOSITE_RESET_END"
            and row["nodeHandle"] != root_node
        )
        reset_node = leaf_reset["nodeHandle"]
        current = leaf_reset["currentNodeHandleAfter"]
        next_handle = max(
            value for row in records for key, value in row.items()
            if key.endswith("Handle") and type(value) is int
        ) + 1
        reset = [
            {"sequence": 0, "event": "COMPOSITE_RESET_BEGIN",
             "threadHandle": 1, "resetHandle": next_handle,
             "rootHandle": root, "nodeHandle": reset_node,
             "contextKind": "ROOT_UPDATE", "contextHandle": call,
             "dispatchHandle": None, "completeBefore": False,
             "currentNodeHandleBefore": current},
            {"sequence": 0, "event": "COMPOSITE_RESET_END",
             "threadHandle": 1, "resetHandle": next_handle,
             "rootHandle": root, "nodeHandle": reset_node,
             "completeAfter": False, "currentNodeHandleAfter": current},
        ]
        records[update_end:update_end] = reset
        renumber(records)
        self.assert_rejected(trace, "native scheduler lifecycle")

    def test_native_repeat_completion_authorizes_exact_recursive_reset(self):
        trace = native_repeat_reset_document()
        result = facts.validate_native_udsp_facts(trace)
        self.assertEqual(result["eventCounts"]["ROOT_UPDATE_BEGIN"], 7)
        self.assertEqual(result["eventCounts"]["COMPOSITE_RESET_BEGIN"], 6)

        bad = copy.deepcopy(trace)
        runtime_reset = next(
            row for row in bad["records"]
            if row["event"] == "COMPOSITE_RESET_BEGIN"
            and row["contextKind"] == "ROOT_UPDATE"
        )
        runtime_reset["completeBefore"] = False
        self.assert_rejected(bad, "prestate")

    def test_callback_is_standalone_and_validates_native_transition(self):
        facts.validate_native_udsp_facts(valid_document())
        trace = valid_document()
        callback = next(row for row in trace["records"] if row["event"] == "CALLBACK")
        callback["callbackCode"] = 2
        callback["completeAfter"] = True
        self.assert_rejected(trace, "non-completion callback")
        trace = valid_document()
        callback = next(row for row in trace["records"] if row["event"] == "CALLBACK")
        callback["returnU32"] = 0
        self.assert_rejected(trace, "return value")

    def test_callback_requires_exact_arm_and_allows_native_repeated_event_one(self):
        trace = valid_document()
        callback = next(row for row in trace["records"]
                        if row["event"] == "CALLBACK")
        duplicate = copy.deepcopy(callback)
        duplicate["sequence"] = len(trace["records"])
        duplicate["completeBefore"] = True
        duplicate["completeAfter"] = True
        trace["records"].append(duplicate)
        result = facts.validate_native_udsp_facts(trace)
        self.assertEqual(result["eventCounts"]["CALLBACK"], 2)

        trace = valid_document()
        arm = next(row for row in trace["records"]
                   if row["event"] == "CALLBACK_ARM")
        arm["modifierId"] = MODIFIER_IDS["WAIT_RANDOM"]
        self.assert_rejected(trace, "modifier differs")

        records = []
        thread, next_handle = allocate_thread(records, 1)
        script, handles, parse_handle, next_handle = add_parse(
            records, "data/Scripts/Characters/atle/stand.def",
            next_handle, thread,
        )
        animation = find_command(script, handles, 3)
        add(
            records, "CALLBACK", thread,
            armHandle=next_handle, parseHandle=parse_handle,
            nodeHandle=animation, rootHandle=None, callHandle=None,
            dispatchHandle=None, callbackCode=1, completeBefore=False,
            completeAfter=True, returnU32=1,
        )
        self.assert_rejected(document(records), "unknown arm")

    def test_cross_thread_callback_can_arrive_after_arm_before_dispatch_end(self):
        trace = valid_document(callback_thread=True)
        result = facts.validate_native_udsp_facts(trace)
        self.assertEqual(result["eventCounts"]["CALLBACK_ARM"], 1)
        self.assertEqual(result["eventCounts"]["CALLBACK"], 1)

    def test_started_animation_dispatch_cannot_publish_a_new_arm(self):
        positive = valid_document()
        facts.validate_native_udsp_facts(positive)
        bad = valid_document(rearm_started=True)
        self.assert_rejected(bad, "started animation dispatch")

    def test_dispatch_started_latch_requires_an_exact_native_exit_branch(self):
        fixtures = []

        ordinary = valid_document(callback=False)
        fixtures.append((ordinary, next(
            row["dispatchHandle"] for row in ordinary["records"]
            if row["event"] == "DISPATCH_BEGIN"
        )))

        callback = valid_document()
        arm = next(row for row in callback["records"]
                   if row["event"] == "CALLBACK_ARM")
        fixtures.append((callback, arm["dispatchHandle"]))

        nested = allfinished_document(
            stop_after_update=4, preparse_for_nested_start=True,
        )
        start = next(row for row in nested["records"]
                     if row["event"] == "ROOT_START_BEGIN"
                     and row["causeDispatchHandle"] is not None)
        fixtures.append((nested, start["causeDispatchHandle"]))

        for trace, dispatch_handle in fixtures:
            with self.subTest(dispatchHandle=dispatch_handle):
                end = next(
                    row for row in trace["records"]
                    if row["event"] == "DISPATCH_END"
                    and row["dispatchHandle"] == dispatch_handle
                )
                end["startedAfter"] = False
                self.assert_rejected(trace, "immediate-complete branch")

        native_no_context = allfinished_document(stop_after_update=0)
        position = next(
            row for row in native_no_context["records"]
            if row["event"] == "DISPATCH_BEGIN" and row["commandId"] == 9
        )
        position_end = next(
            row for row in native_no_context["records"]
            if row["event"] == "DISPATCH_END"
            and row["dispatchHandle"] == position["dispatchHandle"]
        )
        position_end.update(startedAfter=False, exitSiteCode=3)
        facts.validate_native_udsp_facts(native_no_context)

        wrong_site = copy.deepcopy(native_no_context)
        next(row for row in wrong_site["records"]
             if row["event"] == "DISPATCH_END" and row["commandId"] == 9)[
                 "exitSiteCode"
             ] = 2
        self.assert_rejected(wrong_site, "immediate-complete branch")

        started = valid_document(callback=False, repeat_wait_random=True)
        repeated = [row for row in started["records"]
                    if row["event"] == "DISPATCH_BEGIN"
                    and row["commandId"] == 15][-1]
        repeated_end = next(row for row in started["records"]
                            if row["event"] == "DISPATCH_END"
                            and row["dispatchHandle"] == repeated["dispatchHandle"])
        repeated_end["startedAfter"] = False
        self.assert_rejected(started, "started latch")

    def test_dispatch_prestates_are_not_attacker_controlled(self):
        trace = valid_document(callback=False)
        begin = next(row for row in trace["records"]
                     if row["event"] == "DISPATCH_BEGIN")
        begin["completeBefore"] = True
        begin["startedBefore"] = True
        self.assert_rejected(trace, "completion prestate")

    def test_opcode_6_rng_is_first_class_and_wrong_rng_bindings_fail(self):
        trace = allfinished_document(stop_after_update=2)
        result = facts.validate_native_udsp_facts(trace)
        self.assertIn(6, result["capabilities"]["coveredCommandIds"])
        rng = next(
            row for row in trace["records"]
            if row["event"] == "RNG_DRAW"
            and next(
                dispatch["commandId"] for dispatch in trace["records"]
                if dispatch["event"] == "DISPATCH_BEGIN"
                and dispatch["dispatchHandle"] == row["dispatchHandle"]
            ) == 6
        )
        rng["rawRandU15"] = 32768
        self.assert_rejected(trace, "raw rand")

    def test_rng_draw_count_is_exact_and_wait_random_draws_only_on_first_start(self):
        repeated = valid_document(callback=False, repeat_wait_random=True)
        result = facts.validate_native_udsp_facts(repeated)
        self.assertEqual(result["capabilities"]["rng"], {
            "supported": False,
            "status": "VALIDATED_RAW_DRAWS_SEED_AND_GLOBAL_ORDER_UNPROVEN",
            "structuralRawDrawCount": 1,
        })

        redispatch_draw = valid_document(
            callback=False, repeat_wait_random=True,
            rng_on_wait_redispatch=True,
        )
        self.assert_rejected(redispatch_draw, "outside the native initial start branch")

        duplicate = valid_document(callback=False)
        rng_index = next(index for index, row in enumerate(duplicate["records"])
                         if row["event"] == "RNG_DRAW")
        second = copy.deepcopy(duplicate["records"][rng_index])
        second["drawOrdinal"] = 1
        duplicate["records"].insert(rng_index + 1, second)
        renumber(duplicate["records"])
        self.assert_rejected(duplicate, "outside the native initial start branch")

    def test_all_raw_float32_bit_patterns_are_accepted(self):
        for bits in ("7f800000", "ff800000", "7fc00001", "ffffffff", "80000000"):
            with self.subTest(bits=bits):
                trace = valid_document()
                for row in trace["records"]:
                    if row["event"] in {"ROOT_UPDATE_BEGIN", "DISPATCH_BEGIN"}:
                        row["deltaF32Bits"] = bits
                facts.validate_native_udsp_facts(trace)
        trace = valid_document()
        next(row for row in trace["records"]
             if row["event"] == "ROOT_UPDATE_BEGIN")["deltaF32Bits"] = "123"
        self.assert_rejected(trace, "float32 bits")

    def test_effect_events_are_rejected_instead_of_accepted_as_unsupported(self):
        trace = valid_document()
        callback_index = next(i for i, row in enumerate(trace["records"])
                              if row["event"] == "CALLBACK")
        trace["records"].insert(callback_index, {
            "sequence": 0, "event": "EFFECT_BEGIN", "threadHandle": 1,
        })
        renumber(trace["records"])
        self.assert_rejected(trace, "unknown native fact event")

    def test_terminal_hook_failure_anywhere_invalidates_proof(self):
        trace = valid_document()
        update_end = next(i for i, row in enumerate(trace["records"])
                          if row["event"] == "ROOT_UPDATE_END")
        trace["records"] = trace["records"][:update_end]
        add(trace["records"], "HOOK_FAILURE", 1, hookCode=5, errorCode=2)
        self.assert_rejected(trace, "invalidates native proof")
        trace = valid_document()
        trace["records"].insert(2, {
            "sequence": 0, "event": "HOOK_FAILURE", "threadHandle": 1,
            "hookCode": 5, "errorCode": 2,
        })
        renumber(trace["records"])
        self.assert_rejected(trace, "terminal")

    def test_root_generations_restart_update_ordinals_and_track_running_state(self):
        records = []
        thread, next_handle = allocate_thread(records, 1)
        _, handles, parse_handle, next_handle = add_parse(
            records, "data/Scripts/Characters/atle/stand.def",
            next_handle, thread,
        )
        _, next_handle = add_root_start(
            records, next_handle, thread, parse_handle, handles[()], None,
        )
        _, next_handle = add_root_start(
            records, next_handle, thread, parse_handle, handles[()],
            handles[(0,)], running_before=True,
        )
        trace = document(records)
        facts.validate_native_udsp_facts(trace)
        bad = copy.deepcopy(trace)
        starts = [row for row in bad["records"] if row["event"] == "ROOT_START_BEGIN"]
        starts[-1]["runningBefore"] = False
        self.assert_rejected(bad, "running state differs")

    def test_root_update_running_completion_invariant_and_stopped_noop(self):
        trace = valid_document(callback=False)
        end = next(row for row in trace["records"]
                   if row["event"] == "ROOT_UPDATE_END")
        end["runningAfter"] = True
        end["completeAfter"] = True
        self.assert_rejected(trace, "post-state")

        trace = allfinished_document(stop_after_update=7)
        records = trace["records"]
        final_end = [row for row in records
                     if row["event"] == "ROOT_UPDATE_END"][-1]
        root = final_end["rootHandle"]
        next_handle = max(
            value for row in records for key, value in row.items()
            if key.endswith("Handle") and type(value) is int
        ) + 1
        add(
            records, "ROOT_UPDATE_BEGIN", 1,
            callHandle=next_handle, rootHandle=root, updateOrdinal=8,
            deltaF32Bits="00000000", runningBefore=False,
            completeBefore=True,
        )
        add(
            records, "ROOT_UPDATE_END", 1,
            callHandle=next_handle, rootHandle=root,
            runningAfter=True, completeAfter=False,
        )
        self.assert_rejected(trace, "not a native no-op")

    def test_stopped_root_update_rejects_nested_side_events(self):
        def stopped_prefix():
            trace = allfinished_document(stop_after_update=7)
            records = trace["records"]
            final_end = [row for row in records
                         if row["event"] == "ROOT_UPDATE_END"][-1]
            root = final_end["rootHandle"]
            next_handle = max(
                value for row in records for key, value in row.items()
                if key.endswith("Handle") and type(value) is int
            ) + 1
            add(
                records, "ROOT_UPDATE_BEGIN", 1,
                callHandle=next_handle, rootHandle=root, updateOrdinal=8,
                deltaF32Bits="00000000", runningBefore=False,
                completeBefore=True,
            )
            return trace, root, next_handle

        trace, root, call = stopped_prefix()
        command = next(row for row in trace["records"]
                       if row["event"] == "DISPATCH_BEGIN")
        add(
            trace["records"], "DISPATCH_BEGIN", 1,
            callHandle=call, dispatchHandle=call + 1, rootHandle=root,
            nodeHandle=command["nodeHandle"], commandId=command["commandId"],
            deltaF32Bits="00000000", completeBefore=False,
            startedBefore=True,
        )
        self.assert_rejected(trace, "exact ROOT_UPDATE_END")

        trace, root, call = stopped_prefix()
        root_node = next(row["rootNodeHandle"] for row in trace["records"]
                         if row["event"] == "ROOT_START_BEGIN")
        add(
            trace["records"], "COMPOSITE_RESET_BEGIN", 1,
            resetHandle=call + 1, rootHandle=root, nodeHandle=root_node,
            contextKind="ROOT_UPDATE", contextHandle=call,
            dispatchHandle=None, completeBefore=True,
            currentNodeHandleBefore=None,
        )
        self.assert_rejected(trace, "exact ROOT_UPDATE_END")

        trace, root, call = stopped_prefix()
        add(
            trace["records"], "PARSE_BEGIN", 1,
            parseHandle=call + 1,
            sourcePathBytesHex=source_bytes(
                "data/Scripts/Characters/brejton/stand.def"
            ),
            causeCallHandle=None, causeDispatchHandle=None,
        )
        self.assert_rejected(trace, "exact ROOT_UPDATE_END")

    def test_stopped_update_rejects_events_from_an_already_open_parse(self):
        trace = allfinished_document(stop_after_update=7)
        records = trace["records"]
        final_end = [row for row in records
                     if row["event"] == "ROOT_UPDATE_END"][-1]
        root = final_end["rootHandle"]
        next_handle = max(
            value for row in records for key, value in row.items()
            if key.endswith("Handle") and type(value) is int
        ) + 1
        parse_handle, call_handle, node_handle = (
            next_handle, next_handle + 1, next_handle + 2,
        )
        add(
            records, "PARSE_BEGIN", 1, parseHandle=parse_handle,
            sourcePathBytesHex=source_bytes(
                "data/Scripts/Characters/brejton/stand.def"
            ),
            causeCallHandle=None, causeDispatchHandle=None,
        )
        add(
            records, "ROOT_UPDATE_BEGIN", 1,
            callHandle=call_handle, rootHandle=root, updateOrdinal=8,
            deltaF32Bits="00000000", runningBefore=False,
            completeBefore=True,
        )
        add(
            records, "GRAPH_NODE", 1, parseHandle=parse_handle,
            nodeHandle=node_handle, parentHandle=None, childOrdinal=0,
            nodeType=4, repeat=False,
        )
        self.assert_rejected(trace, "open parser permits only")

    def test_scheduler_order_and_early_finish_are_fail_closed(self):
        trace = valid_document(callback=False)
        dispatches = [row for row in trace["records"]
                      if row["event"] == "DISPATCH_BEGIN"]
        first, second = dispatches[:2]
        first_node, second_node = first["nodeHandle"], second["nodeHandle"]
        first["nodeHandle"], second["nodeHandle"] = second_node, first_node
        for row in trace["records"]:
            if row["event"] == "DISPATCH_END":
                if row["nodeHandle"] == first_node:
                    row["nodeHandle"] = second_node
                elif row["nodeHandle"] == second_node:
                    row["nodeHandle"] = first_node
        self.assert_rejected(trace, "scheduler order")

        trace = valid_document(callback=False)
        first = next(row for row in trace["records"]
                     if row["event"] == "DISPATCH_BEGIN")
        non_current = [row for row in trace["records"]
                       if row["event"] == "GRAPH_NODE"
                       and row["nodeType"] == 6][-1]
        first["nodeHandle"] = non_current["nodeHandle"]
        first_end = next(row for row in trace["records"]
                         if row["event"] == "ROOT_UPDATE_END")
        first_end["runningAfter"] = False
        first_end["completeAfter"] = True
        self.assert_rejected(trace, "scheduler order")

    def test_constructor_events_and_old_single_events_are_not_wire_events(self):
        for event in ("COMMAND_CONSTRUCT", "COMPOSITE_CONSTRUCT", "ROOT_START",
                      "COMPOSITE_RESET"):
            with self.subTest(event=event):
                trace = valid_document()
                add(trace["records"], event, 1)
                self.assert_rejected(trace, "unknown native fact event")

    def test_graph_identity_shape_sequence_and_handle_invariants_remain_fail_closed(self):
        trace = valid_document()
        trace["records"][2]["sequence"] = 99
        self.assert_rejected(trace, "sequence")
        trace = valid_document()
        node = next(row for row in trace["records"] if row["event"] == "GRAPH_NODE")
        node["nodeHandle"] = 0x0043CD70
        self.assert_rejected(trace, "contiguous observer id")
        trace = valid_document()
        command = next(row for row in trace["records"]
                       if row["event"] == "GRAPH_NODE" and row["nodeType"] == 6)
        command["commandId"] = 12
        self.assert_rejected(trace, "command id differs")
        trace = valid_document()
        trace["records"][1]["nodePointer"] = 123
        self.assert_rejected(trace, "pointer-shaped key")

    def test_parser_graph_order_is_the_native_source_depth_first_order(self):
        trace = valid_document(callback=False)
        reorder_graph_breadth_first(trace)
        self.assert_rejected(trace, "source token order")

    def test_bool_is_not_an_integer_and_semantic_labels_remain_forbidden(self):
        trace = valid_document()
        trace["schema"] = True
        self.assert_rejected(trace, "identity")
        for key in ("scriptKey", "opcodeName", "modifierName", "parityEligible"):
            with self.subTest(key=key):
                trace = valid_document()
                trace["records"][1][key] = "forged"
                self.assert_rejected(trace, "semantic label")


if __name__ == "__main__":
    unittest.main()
