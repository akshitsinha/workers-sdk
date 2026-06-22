import {
	createWorkflowInstanceIntrospector,
	createWorkflowIntrospector,
} from "@cloudflare/workflows-shared/src/testing";
import type {
	WorkflowBinding,
	WorkflowInstanceIntrospector,
	WorkflowIntrospector,
} from "@cloudflare/workflows-shared/src/testing";

// Note(osilva): `introspectWorkflowInstance()` doesn’t need to be async, but we keep it that way
// to avoid potential breaking changes later and to stay consistent with `introspectWorkflow`.

// In the "cloudflare:test" module, the exposed type is `Workflow`. Here we use `WorkflowBinding`
// (which implements `Workflow`) to access unsafe functions.
export async function introspectWorkflowInstance(
	workflow: WorkflowBinding,
	instanceId: string
): Promise<WorkflowInstanceIntrospector> {
	if (!workflow || !instanceId) {
		throw new Error(
			"[WorkflowIntrospector] Workflow binding and instance id are required."
		);
	}
	return createWorkflowInstanceIntrospector(workflow, instanceId);
}

// Note(osilva): `introspectWorkflow` could be sync with some changes, but we keep it async
// to avoid potential breaking changes later.

// In the "cloudflare:test" module, the exposed type is `Workflow`. Here we use `WorkflowBinding`
// (which implements `Workflow`) to access unsafe functions.
export async function introspectWorkflow(
	workflow: WorkflowBinding
): Promise<WorkflowIntrospector> {
	if (!workflow) {
		throw new Error("[WorkflowIntrospector] Workflow binding is required.");
	}

	return createWorkflowIntrospector(workflow);
}
