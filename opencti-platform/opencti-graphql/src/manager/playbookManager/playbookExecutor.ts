import moment from 'moment';
import * as jsonpatch from 'fast-json-patch';
import type { ComponentDefinition, PlaybookExecution, PlaybookExecutionStep } from '../../modules/playbook/playbook-types';
import type { StixBundle } from '../../types/stix-2-1-common';
import { utcDate } from '../../utils/format';
import type { ExecutionEnvelop, ExecutionEnvelopStep } from '../../types/playbookExecution';
import { redisPlaybookUpdate } from '../../database/redis';
import { logApp } from '../../config/conf';
import { UnsupportedError } from '../../config/errors';
import { PLAYBOOK_COMPONENTS } from '../../modules/playbook/playbook-components';
import type { StreamDataEvent } from '../../types/event';

// Only way to force the step_literal checking
// Don't try to understand, just trust
function keyStep<V>(k: `step_${string}`, v: V): { [P in `step_${string}`]: V } {
  return { [k]: v } as any; // Trust the entry checking
}

type ObservationFn = {
  message: string,
  status: 'success' | 'error',
  executionId: string,
  playbookId: string,
  start: string,
  end: string,
  diff: number,
  previousStepId?: string,
  stepId: string,
  previousBundle?: StixBundle | null
  bundle?: StixBundle | null
  error?: string
  forceBundleTracking: boolean
};

const registerStepObservation = async (data: ObservationFn) => {
  const patch = data.previousBundle && data.bundle ? jsonpatch.compare(data.previousBundle, data.bundle) : [];
  const bundlePatch = data.previousStepId && !data.forceBundleTracking ? { patch } : { bundle: data.bundle };
  const step: ExecutionEnvelopStep = {
    message: data.message,
    status: data.status,
    previous_step_id: data.previousStepId,
    in_timestamp: data.start,
    out_timestamp: data.end,
    duration: data.diff,
    error: data.error,
    ...bundlePatch
  };
  const envelop: ExecutionEnvelop = {
    playbook_execution_id: data.executionId,
    playbook_id: data.playbookId,
    last_execution_step: data.stepId,
    ...keyStep(`step_${data.stepId}`, step)
  };
  await redisPlaybookUpdate(envelop);
};

type ExecutorFn = {
  eventId: string,
  executionId: string,
  playbookId: string,
  dataInstanceId: string,
  definition: ComponentDefinition,
  previousStep: PlaybookExecutionStep<object> | null
  nextStep: PlaybookExecutionStep<object>,
  previousStepBundle: StixBundle | null
  bundle: StixBundle
  event?:StreamDataEvent,
  externalCallback?: {
    externalStartDate: Date
  }
};

export const playbookExecutor = async ({
  eventId,
  executionId,
  playbookId,
  dataInstanceId,
  definition,
  previousStep,
  nextStep,
  previousStepBundle,
  bundle,
  event,
  externalCallback
} : ExecutorFn) => {
  const isExternalCallback = externalCallback !== undefined;
  const start = isExternalCallback ? externalCallback.externalStartDate : utcDate();
  const instanceWithConfig = { ...nextStep.instance, configuration: JSON.parse(nextStep.instance.configuration ?? '{}') };
  if (nextStep.component.is_internal || isExternalCallback) {
    let execution: PlaybookExecution;
    const baseBundle = structuredClone(isExternalCallback ? previousStepBundle : bundle);
    try {
      execution = await nextStep.component.executor({
        event,
        eventId,
        executionId,
        dataInstanceId,
        playbookId,
        previousPlaybookNodeId: previousStep?.instance.id,
        previousStepBundle,
        playbookNode: instanceWithConfig,
        bundle
      });
      // Execution was done correctly, log the step
      // For internal component, register directly the observability
      const end = utcDate();
      const durationDiff = end.diff(start);
      const duration = moment.duration(durationDiff);
      const observation: ObservationFn = {
        message: `${nextStep.instance.name.trim()} successfully executed in ${duration.humanize()}`,
        status: 'success',
        executionId,
        previousStepId: previousStep?.instance?.id,
        stepId: nextStep.instance.id,
        start: start.toISOString(),
        end: end.toISOString(),
        diff: durationDiff,
        playbookId,
        previousBundle: baseBundle,
        bundle: execution.bundle,
        forceBundleTracking: execution.forceBundleTracking ?? false
      };
      await registerStepObservation(observation);
    } catch (error) {
      // Error executing the step, register
      const executionError = error as Error;
      logApp.error('[OPENCTI-MODULE] Playbook manager executor error', { cause: error, manager: 'PLAYBOOK_MANAGER', step: instanceWithConfig, bundle: baseBundle });
      const end = utcDate();
      const durationDiff = end.diff(start);
      const duration = moment.duration(durationDiff);
      const logError = { message: executionError.message, stack: executionError.stack, name: executionError.name };
      const observation: ObservationFn = {
        message: `${nextStep.component.name.trim()} fail execution in ${duration.humanize()}`,
        status: 'error',
        executionId,
        previousStepId: undefined,
        stepId: nextStep.instance.id,
        start: start.toISOString(),
        end: end.toISOString(),
        diff: durationDiff,
        playbookId,
        bundle: baseBundle,
        error: JSON.stringify(logError, null, 2),
        forceBundleTracking: false
      };
      await registerStepObservation(observation);
      return;
    }
    // Send the result to the next component if needed
    if (execution.output_port) {
      // Find the next op for this attachment
      const connections = definition.links.filter((c) => c.from.id === nextStep.instance.id && c.from.port === execution.output_port);
      for (let connectionIndex = 0; connectionIndex < connections.length; connectionIndex += 1) {
        const connection = connections[connectionIndex];
        const nextInstance = definition.nodes.find((c) => c.id === connection.to.id);
        const fromInstance = definition.nodes.find((c) => c.id === connection.from.id);
        if (!nextInstance || !fromInstance) {
          throw UnsupportedError('Invalid playbook, nextInstance needed');
        }
        const fromConnector = PLAYBOOK_COMPONENTS[fromInstance.component_id];
        const nextConnector = PLAYBOOK_COMPONENTS[nextInstance.component_id];
        await playbookExecutor({
          event,
          eventId,
          executionId,
          playbookId,
          dataInstanceId,
          definition,
          previousStep: { component: fromConnector, instance: fromInstance },
          nextStep: { component: nextConnector, instance: nextInstance },
          previousStepBundle,
          bundle: execution.bundle
        });
      }
    }
  } else {
    if (!nextStep.component.notify) {
      throw UnsupportedError('Notify definition is required');
    }
    // Component must rely on an external call.
    // Execution will be continued through an external API call
    try {
      await nextStep.component.notify({
        event,
        eventId,
        executionId,
        dataInstanceId,
        playbookId,
        previousPlaybookNodeId: previousStep?.instance.id,
        playbookNode: instanceWithConfig,
        previousStepBundle,
        bundle
      });
    } catch (_notifyError) {
      // For now any problem sending in notification will not be tracked
    }
  }
};
