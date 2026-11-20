/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

export interface PlaybookExecutionStepInput {
  readonly id: string;
  readonly status?: string | null;
  readonly duration?: number | null;
}

export interface PlaybookExecutionInput {
  readonly id: string;
  readonly execution_start?: string | null;
  readonly steps?: ReadonlyArray<PlaybookExecutionStepInput> | null;
}

export type PlaybookStepOutcome = 'success' | 'error';

export interface PlaybookNodeLastExecution {
  status: PlaybookStepOutcome;
  duration: number | null;
  executionId: string;
}

// The newest execution first: the backend lists them as stored, so the order is read from execution_start,
// then from the execution id, never from the array order.
const newestFirst = (a: PlaybookExecutionInput, b: PlaybookExecutionInput) => {
  const byStart = (b.execution_start ?? '').localeCompare(a.execution_start ?? '');
  return byStart !== 0 ? byStart : b.id.localeCompare(a.id);
};

// The outcome of each step in the most recent execution that ran it. A step id is
// "<execution id>-<node id>" (the backend prefixes it to keep Relay ids unique), so the node id
// is what follows the execution id. A node that never ran has no entry: the canvas shows no badge.
export const lastExecutionByNode = (
  executions: ReadonlyArray<PlaybookExecutionInput> | null | undefined,
): Map<string, PlaybookNodeLastExecution> => {
  const result = new Map<string, PlaybookNodeLastExecution>();
  [...(executions ?? [])].sort(newestFirst).forEach((execution) => {
    const prefix = `${execution.id}-`;
    (execution.steps ?? []).forEach((step) => {
      if (!step.id.startsWith(prefix)) return;
      const nodeId = step.id.slice(prefix.length);
      if (!nodeId || result.has(nodeId)) return;
      result.set(nodeId, {
        status: step.status === 'success' ? 'success' : 'error',
        duration: typeof step.duration === 'number' ? step.duration : null,
        executionId: execution.id,
      });
    });
  });
  return result;
};

// A duration in milliseconds, short enough for a badge: 840 ms, 2.4 s, 3 min 5 s.
export const formatStepDuration = (duration: number | null): string | null => {
  if (duration === null || duration < 0) return null;
  if (duration < 1000) return `${Math.round(duration)} ms`;
  if (duration < 60000) return `${(duration / 1000).toFixed(duration < 10000 ? 1 : 0)} s`;
  const minutes = Math.floor(duration / 60000);
  const seconds = Math.round((duration % 60000) / 1000);
  return seconds > 0 ? `${minutes} min ${seconds} s` : `${minutes} min`;
};
