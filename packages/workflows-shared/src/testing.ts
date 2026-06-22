export type WorkflowStepSelector = {
	name: string;
	index?: number;
};

export type WorkflowInstanceModifier = {
	disableSleeps(steps?: WorkflowStepSelector[]): Promise<void>;
	disableRetryDelays(steps?: WorkflowStepSelector[]): Promise<void>;
	mockStepResult(
		step: WorkflowStepSelector,
		stepResult: unknown
	): Promise<void>;
	mockStepError(
		step: WorkflowStepSelector,
		error: Error,
		times?: number
	): Promise<void>;
	forceStepTimeout(step: WorkflowStepSelector, times?: number): Promise<void>;
	mockEvent(event: { type: string; payload: unknown }): Promise<void>;
	forceEventTimeout(step: WorkflowStepSelector): Promise<void>;
};

export type WorkflowIntrospectionOperation =
	| { type: "disableSleeps"; steps?: WorkflowStepSelector[] }
	| { type: "disableRetryDelays"; steps?: WorkflowStepSelector[] }
	| {
			type: "mockStepResult";
			step: WorkflowStepSelector;
			stepResult: unknown;
	  }
	| {
			type: "mockStepError";
			step: WorkflowStepSelector;
			error: { name: string; message: string };
			times?: number;
	  }
	| { type: "forceStepTimeout"; step: WorkflowStepSelector; times?: number }
	| { type: "mockEvent"; event: { type: string; payload: unknown } }
	| { type: "forceEventTimeout"; step: WorkflowStepSelector };

export type WorkflowBinding = {
	unsafeGetInstanceModifier(
		instanceId: string
	): Promise<WorkflowInstanceModifier>;
	unsafeWaitForStepResult(
		instanceId: string,
		name: string,
		index?: number
	): Promise<unknown>;
	unsafeWaitForStatus(instanceId: string, status: string): Promise<void>;
	unsafeGetOutputOrError(
		instanceId: string,
		isOutput: boolean
	): Promise<unknown>;
	unsafeAbort(instanceId: string, reason?: string): Promise<void>;
	unsafeStartIntrospection(
		operations: WorkflowIntrospectionOperation[]
	): Promise<string>;
	unsafeSetIntrospectionOperations(
		sessionId: string,
		operations: WorkflowIntrospectionOperation[]
	): Promise<void>;
	unsafeStopIntrospection(sessionId: string): Promise<void>;
	unsafeGetIntrospectionInstances(sessionId: string): Promise<string[]>;
};

export type ModifierCallback = (
	modifier: WorkflowInstanceModifier
) => Promise<void>;

export interface WorkflowInstanceIntrospector {
	modify(fn: ModifierCallback): Promise<WorkflowInstanceIntrospector>;
	waitForStepResult(step: WorkflowStepSelector): Promise<unknown>;
	waitForStatus(status: string): Promise<void>;
	getOutput(): Promise<unknown>;
	getError(): Promise<{ name: string; message: string }>;
	dispose(): Promise<void>;
	[Symbol.asyncDispose](): Promise<void>;
}

export interface WorkflowIntrospector {
	modifyAll(fn: ModifierCallback): Promise<void>;
	get(): Promise<WorkflowInstanceIntrospector[]>;
	dispose(): Promise<void>;
	[Symbol.asyncDispose](): Promise<void>;
}

export function createWorkflowInstanceIntrospector(
	workflow: WorkflowBinding,
	instanceId: string
): WorkflowInstanceIntrospector {
	return new WorkflowInstanceIntrospectorHandle(workflow, instanceId);
}

export async function createWorkflowIntrospector(
	workflow: WorkflowBinding
): Promise<WorkflowIntrospector> {
	const operations: WorkflowIntrospectionOperation[] = [];
	const sessionId = await workflow.unsafeStartIntrospection(operations);

	return new WorkflowIntrospectorHandle(workflow, sessionId, operations);
}

class RecordingWorkflowInstanceModifier implements WorkflowInstanceModifier {
	constructor(private readonly operations: WorkflowIntrospectionOperation[]) {}

	async disableSleeps(steps?: WorkflowStepSelector[]): Promise<void> {
		this.operations.push({ type: "disableSleeps", steps });
	}

	async disableRetryDelays(steps?: WorkflowStepSelector[]): Promise<void> {
		this.operations.push({ type: "disableRetryDelays", steps });
	}

	async mockStepResult(
		step: WorkflowStepSelector,
		stepResult: unknown
	): Promise<void> {
		this.operations.push({ type: "mockStepResult", step, stepResult });
	}

	async mockStepError(
		step: WorkflowStepSelector,
		error: Error,
		times?: number
	): Promise<void> {
		this.operations.push({
			type: "mockStepError",
			step,
			error: { name: error.name, message: error.message },
			times,
		});
	}

	async forceStepTimeout(
		step: WorkflowStepSelector,
		times?: number
	): Promise<void> {
		this.operations.push({ type: "forceStepTimeout", step, times });
	}

	async mockEvent(event: { type: string; payload: unknown }): Promise<void> {
		this.operations.push({ type: "mockEvent", event });
	}

	async forceEventTimeout(step: WorkflowStepSelector): Promise<void> {
		this.operations.push({ type: "forceEventTimeout", step });
	}
}

class WorkflowIntrospectorHandle implements WorkflowIntrospector {
	readonly #instanceIntrospectors = new Map<
		string,
		WorkflowInstanceIntrospector
	>();
	#disposed = false;

	constructor(
		private readonly workflow: WorkflowBinding,
		private readonly sessionId: string,
		private readonly operations: WorkflowIntrospectionOperation[]
	) {}

	async modifyAll(fn: ModifierCallback): Promise<void> {
		await fn(new RecordingWorkflowInstanceModifier(this.operations));
		await this.workflow.unsafeSetIntrospectionOperations(
			this.sessionId,
			this.operations
		);
	}

	async get(): Promise<WorkflowInstanceIntrospector[]> {
		const instanceIds = await this.workflow.unsafeGetIntrospectionInstances(
			this.sessionId
		);

		for (const instanceId of instanceIds) {
			if (!this.#instanceIntrospectors.has(instanceId)) {
				this.#instanceIntrospectors.set(
					instanceId,
					createWorkflowInstanceIntrospector(this.workflow, instanceId)
				);
			}
		}

		return Array.from(this.#instanceIntrospectors.values());
	}

	dispose = async (): Promise<void> => {
		if (this.#disposed) {
			return;
		}
		this.#disposed = true;

		await this.workflow.unsafeStopIntrospection(this.sessionId);
		await Promise.all(
			Array.from(this.#instanceIntrospectors.values(), (introspector) =>
				introspector.dispose()
			)
		);
		this.#instanceIntrospectors.clear();
	};

	async [Symbol.asyncDispose](): Promise<void> {
		await this.dispose();
	}
}

class WorkflowInstanceIntrospectorHandle implements WorkflowInstanceIntrospector {
	#instanceModifier: WorkflowInstanceModifier | undefined;
	#instanceModifierPromise: Promise<WorkflowInstanceModifier> | undefined;

	constructor(
		private readonly workflow: WorkflowBinding,
		private readonly instanceId: string
	) {
		this.#instanceModifierPromise = workflow
			.unsafeGetInstanceModifier(instanceId)
			.then((modifier) => {
				this.#instanceModifier = modifier as WorkflowInstanceModifier;
				this.#instanceModifierPromise = undefined;
				return this.#instanceModifier;
			});
	}

	async modify(fn: ModifierCallback): Promise<WorkflowInstanceIntrospector> {
		if (this.#instanceModifierPromise !== undefined) {
			this.#instanceModifier = await this.#instanceModifierPromise;
		}
		if (this.#instanceModifier === undefined) {
			throw new Error(
				"could not apply modifications due to internal error. Retrying the test may resolve the issue."
			);
		}

		await fn(this.#instanceModifier);

		return this;
	}

	async waitForStepResult(step: WorkflowStepSelector): Promise<unknown> {
		return await this.workflow.unsafeWaitForStepResult(
			this.instanceId,
			step.name,
			step.index
		);
	}

	async waitForStatus(status: string): Promise<void> {
		if (status === "queued") {
			return;
		}

		await this.workflow.unsafeWaitForStatus(this.instanceId, status);
	}

	async getOutput(): Promise<unknown> {
		return await this.workflow.unsafeGetOutputOrError(this.instanceId, true);
	}

	async getError(): Promise<{ name: string; message: string }> {
		return (await this.workflow.unsafeGetOutputOrError(
			this.instanceId,
			false
		)) as { name: string; message: string };
	}

	dispose = async (): Promise<void> => {
		await this.workflow.unsafeAbort(this.instanceId, "Instance dispose");
	};

	async [Symbol.asyncDispose](): Promise<void> {
		await this.dispose();
	}
}
