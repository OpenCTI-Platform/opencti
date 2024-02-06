/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { v4 as uuidv4 } from 'uuid';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import * as jsonpatch from 'fast-json-patch';
import moment from 'moment';
import { createStreamProcessor, lockResource, redisPlaybookUpdate } from '../database/redis';
import conf, { booleanConf, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { utcDate } from '../utils/format';
import { findById } from '../modules/playbook/playbook-domain';
import { PLAYBOOK_COMPONENTS } from '../modules/playbook/playbook-components';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { isNotEmptyField } from '../database/utils';
import { STIX_SPEC_VERSION } from '../database/stix';
import { getEntitiesListFromCache } from '../database/cache';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
const PLAYBOOK_LIVE_KEY = conf.get('playbook_manager:lock_key');
const STREAM_SCHEDULE_TIME = 10000;
// Only way to force the step_literal checking
// Don't try to understand, just trust
function keyStep(k, v) {
    return { [k]: v }; // Trust the entry checking
}
const registerStepObservation = (data) => __awaiter(void 0, void 0, void 0, function* () {
    const patch = data.previousBundle && data.bundle ? jsonpatch.compare(data.previousBundle, data.bundle) : [];
    const bundlePatch = data.previousStepId && !data.forceBundleTracking ? { patch } : { bundle: data.bundle };
    const step = Object.assign({ message: data.message, status: data.status, previous_step_id: data.previousStepId, in_timestamp: data.start, out_timestamp: data.end, duration: data.diff, error: data.error }, bundlePatch);
    const envelop = Object.assign({ playbook_execution_id: data.executionId, playbook_id: data.playbookId, last_execution_step: data.stepId }, keyStep(`step_${data.stepId}`, step));
    yield redisPlaybookUpdate(envelop);
});
export const playbookExecutor = ({ executionId, playbookId, dataInstanceId, definition, previousStep, nextStep, previousStepBundle, bundle, externalCallback }) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c;
    const isExternalCallback = externalCallback !== undefined;
    const start = isExternalCallback ? externalCallback.externalStartDate : utcDate();
    const instanceWithConfig = Object.assign(Object.assign({}, nextStep.instance), { configuration: JSON.parse((_a = nextStep.instance.configuration) !== null && _a !== void 0 ? _a : '{}') });
    if (nextStep.component.is_internal || isExternalCallback) {
        let execution;
        const baseBundle = structuredClone(isExternalCallback ? previousStepBundle : bundle);
        try {
            execution = yield nextStep.component.executor({
                executionId,
                dataInstanceId,
                playbookId,
                previousPlaybookNode: previousStep === null || previousStep === void 0 ? void 0 : previousStep.instance,
                previousStepBundle,
                playbookNode: instanceWithConfig,
                bundle
            });
            // Execution was done correctly, log the step
            // For internal component, register directly the observability
            const end = utcDate();
            const durationDiff = end.diff(start);
            const duration = moment.duration(durationDiff);
            const observation = {
                message: `${nextStep.component.name.trim()} successfully executed in ${duration.humanize()}`,
                status: 'success',
                executionId,
                previousStepId: (_b = previousStep === null || previousStep === void 0 ? void 0 : previousStep.instance) === null || _b === void 0 ? void 0 : _b.id,
                stepId: nextStep.instance.id,
                start: start.toISOString(),
                end: end.toISOString(),
                diff: durationDiff,
                playbookId,
                previousBundle: baseBundle,
                bundle: execution.bundle,
                forceBundleTracking: (_c = execution.forceBundleTracking) !== null && _c !== void 0 ? _c : false
            };
            yield registerStepObservation(observation);
        }
        catch (error) {
            // Error executing the step, register
            const executionError = error;
            logApp.error(error, { step: instanceWithConfig, bundle: baseBundle });
            const end = utcDate();
            const durationDiff = end.diff(start);
            const duration = moment.duration(durationDiff);
            const logError = { message: executionError.message, stack: executionError.stack, name: executionError.name };
            const observation = {
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
            yield registerStepObservation(observation);
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
                yield playbookExecutor({
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
    }
    else {
        if (!nextStep.component.notify) {
            throw UnsupportedError('Notify definition is required');
        }
        // Component must rely on an external call.
        // Execution will be continued through an external API call
        try {
            yield nextStep.component.notify({
                executionId,
                dataInstanceId,
                playbookId,
                previousPlaybookNode: previousStep === null || previousStep === void 0 ? void 0 : previousStep.instance,
                playbookNode: instanceWithConfig,
                previousStepBundle,
                bundle
            });
        }
        catch (notifyError) {
            // For now any problem sending in notification will not be tracked
        }
    }
});
const playbookStreamHandler = (streamEvents) => __awaiter(void 0, void 0, void 0, function* () {
    var _d;
    try {
        if (streamEvents.length === 0) {
            return;
        }
        const context = executionContext('playbook_manager');
        const playbooks = yield getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_PLAYBOOK);
        for (let index = 0; index < streamEvents.length; index += 1) {
            const streamEvent = streamEvents[index];
            const { data: { data, type } } = streamEvent;
            // For each event we need to check ifs
            for (let playbookIndex = 0; playbookIndex < playbooks.length; playbookIndex += 1) {
                const playbook = playbooks[playbookIndex];
                if (playbook.playbook_definition) {
                    const def = JSON.parse(playbook.playbook_definition);
                    // 01. Find the starting point of the playbook
                    const instance = def.nodes.find((n) => n.id === playbook.playbook_start);
                    if (!instance) {
                        throw UnsupportedError('Invalid playbook, entry point needed');
                    }
                    const connector = PLAYBOOK_COMPONENTS[instance.component_id];
                    const { update, create, delete: deletion, filters } = JSON.parse((_d = instance.configuration) !== null && _d !== void 0 ? _d : '{}');
                    const jsonFilters = filters ? JSON.parse(filters) : null;
                    let validEventType = false;
                    if (type === 'create' && create === true)
                        validEventType = true;
                    if (type === 'update' && update === true)
                        validEventType = true;
                    if (type === 'delete' && deletion === true)
                        validEventType = true;
                    const isMatch = yield isStixMatchFilterGroup(context, SYSTEM_USER, data, jsonFilters);
                    // 02. Execute the component
                    if (validEventType && isMatch) {
                        const nextStep = { component: connector, instance };
                        const bundle = { id: uuidv4(), spec_version: STIX_SPEC_VERSION, type: 'bundle', objects: [data] };
                        yield playbookExecutor({
                            // Basic
                            executionId: uuidv4(),
                            playbookId: playbook.id,
                            dataInstanceId: data.id,
                            definition: def,
                            // Steps
                            previousStep: null,
                            nextStep,
                            // Data
                            previousStepBundle: null,
                            bundle,
                        });
                    }
                }
            }
        }
    }
    catch (e) {
        logApp.error(e, { manager: 'PLAYBOOK_MANAGER' });
    }
});
const initPlaybookManager = () => {
    const WAIT_TIME_ACTION = 2000;
    let streamScheduler;
    let streamProcessor;
    let running = false;
    let shutdown = false;
    const wait = (ms) => {
        return new Promise((resolve) => {
            setTimeout(resolve, ms);
        });
    };
    const playbookHandler = () => __awaiter(void 0, void 0, void 0, function* () {
        let lock;
        try {
            // Lock the manager
            lock = yield lockResource([PLAYBOOK_LIVE_KEY], { retryCount: 0 });
            running = true;
            logApp.info('[OPENCTI-MODULE] Running playbook manager');
            streamProcessor = createStreamProcessor(SYSTEM_USER, 'Playbook manager', playbookStreamHandler);
            yield streamProcessor.start('live');
            while (!shutdown && streamProcessor.running()) {
                lock.signal.throwIfAborted();
                yield wait(WAIT_TIME_ACTION);
            }
            logApp.info('[OPENCTI-MODULE] End of playbook manager processing');
        }
        catch (e) {
            if (e.name === TYPE_LOCK_ERROR) {
                logApp.debug('[OPENCTI-MODULE] Playbook manager already started by another API');
            }
            else {
                logApp.error(e, { manager: 'PLAYBOOK_MANAGER' });
            }
        }
        finally {
            if (streamProcessor)
                yield streamProcessor.shutdown();
            if (lock)
                yield lock.unlock();
        }
    });
    return {
        start: () => __awaiter(void 0, void 0, void 0, function* () {
            streamScheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                yield playbookHandler();
            }), STREAM_SCHEDULE_TIME);
        }),
        status: (settings) => {
            return {
                id: 'PLAYBOOK_MANAGER',
                enable: isNotEmptyField(settings === null || settings === void 0 ? void 0 : settings.enterprise_edition) && booleanConf('playbook_manager:enabled', false),
                running,
            };
        },
        shutdown: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Stopping playbook manager');
            shutdown = true;
            if (streamScheduler)
                yield clearIntervalAsync(streamScheduler);
            return true;
        }),
    };
};
export const playbookStepExecution = (context, user, args) => __awaiter(void 0, void 0, void 0, function* () {
    const playbook = yield findById(context, user, args.playbook_id);
    if (!playbook) {
        return false;
    }
    const def = JSON.parse(playbook.playbook_definition);
    const nextInstance = def.nodes.find((n) => n.id === args.step_id);
    const previousInstance = def.nodes.find((n) => n.id === args.previous_step_id);
    if (!nextInstance || !previousInstance) {
        return false;
    }
    const connector = PLAYBOOK_COMPONENTS[nextInstance.component_id];
    // 02. Execute the component
    const nextStep = { component: connector, instance: nextInstance };
    const previousStep = { component: connector, instance: previousInstance };
    // const previousData = JSON.parse(args.previous_data);
    const bundle = JSON.parse(args.bundle);
    return playbookExecutor({
        executionId: args.execution_id,
        playbookId: args.playbook_id,
        dataInstanceId: args.data_instance_id,
        definition: def,
        previousStep,
        nextStep,
        previousStepBundle: JSON.parse(args.previous_bundle),
        bundle,
        externalCallback: {
            externalStartDate: args.execution_start,
        }
    }).then(() => true);
});
const playbookManager = initPlaybookManager();
export default playbookManager;
