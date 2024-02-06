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
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { Promise as BluePromise } from 'bluebird';
import * as R from 'ramda';
import { EVENT_TYPE_UPDATE, isNotEmptyField, waitInSec } from '../database/utils';
import conf, { ENABLED_FILE_INDEX_MANAGER, logApp } from '../config/conf';
import { createStreamProcessor, lockResource, } from '../database/redis';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { isAttachmentProcessorEnabled, } from '../database/engine';
import { elIndexFiles, elUpdateFilesWithEntityRestrictions } from '../database/file-search';
import { getFileContent } from '../database/file-storage';
import { generateFileIndexId } from '../schema/identifier';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { getManagerConfigurationFromCache, updateManagerConfigurationLastRun } from '../modules/managerConfiguration/managerConfiguration-domain';
import { allFilesForPaths, getIndexFromDate } from '../modules/internal/document/document-domain';
import { buildOptionsFromFileManager } from '../domain/file';
import { internalLoadById } from '../database/middleware-loader';
const FILE_INDEX_MANAGER_KEY = conf.get('file_index_manager:lock_key');
const SCHEDULE_TIME = conf.get('file_index_manager:interval') || 60000; // 1 minute
const STREAM_SCHEDULE_TIME = 10000;
const FILE_INDEX_MANAGER_STREAM_KEY = conf.get('file_index_manager:stream_lock_key');
const loadFilesToIndex = (file) => __awaiter(void 0, void 0, void 0, function* () {
    const content = yield getFileContent(file.id, 'base64');
    return {
        internal_id: file.internalId,
        file_id: file.id,
        file_data: content,
        entity_id: file.entityId,
        name: file.name,
        uploaded_at: file.uploaded_at,
    };
});
const indexImportedFiles = (context, indexFromDate) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    const fileOptions = yield buildOptionsFromFileManager(context);
    const opts = Object.assign(Object.assign({}, fileOptions.opts), { modifiedSince: indexFromDate });
    const allFiles = yield allFilesForPaths(context, SYSTEM_USER, (_a = fileOptions.paths) !== null && _a !== void 0 ? _a : [], opts);
    if (allFiles.length === 0) {
        return;
    }
    const filesBulk = R.splitEvery(20, allFiles);
    for (let index = 0; index < filesBulk.length; index += 1) {
        const managerConfiguration = yield getManagerConfigurationFromCache(context, SYSTEM_USER, 'FILE_INDEX_MANAGER');
        if (managerConfiguration === null || managerConfiguration === void 0 ? void 0 : managerConfiguration.manager_running) {
            const filesToLoad = filesBulk[index].map((file) => {
                const internalId = generateFileIndexId(file.id);
                const entityId = file.metaData.entity_id;
                return {
                    id: file.id,
                    internalId,
                    entityId,
                    name: file.name,
                    uploaded_at: file.lastModified,
                };
            });
            const filesToIndex = yield BluePromise.map(filesToLoad, loadFilesToIndex, { concurrency: 5 });
            // index all files one by one
            yield elIndexFiles(context, SYSTEM_USER, filesToIndex);
            yield waitInSec(1);
        }
    }
});
const handleStreamEvents = (streamEvents) => __awaiter(void 0, void 0, void 0, function* () {
    var _b;
    try {
        if (streamEvents.length === 0) {
            return;
        }
        const context = executionContext('file_index_manager');
        for (let index = 0; index < streamEvents.length; index += 1) {
            const event = streamEvents[index];
            if (event.data.type === EVENT_TYPE_UPDATE) {
                const updateEvent = event.data;
                const stix = updateEvent.data;
                const entityId = stix.extensions[STIX_EXT_OCTI].id;
                const entityType = stix.extensions[STIX_EXT_OCTI].type;
                const stixFiles = stix.extensions[STIX_EXT_OCTI].files;
                // test if markings or organization sharing have been updated
                const isDataRestrictionsUpdate = ((_b = updateEvent.context) === null || _b === void 0 ? void 0 : _b.patch) && updateEvent.context.patch
                    .map((op) => op.path && (op.path.includes('granted_refs') || op.path.includes('object_marking_refs')));
                if ((stixFiles === null || stixFiles === void 0 ? void 0 : stixFiles.length) > 0 && isDataRestrictionsUpdate) {
                    // update all indexed files for this entity
                    const entity = yield internalLoadById(context, SYSTEM_USER, entityId, { type: entityType });
                    yield elUpdateFilesWithEntityRestrictions(entity);
                }
            }
        }
    }
    catch (e) {
        logApp.error(e, { manager: 'FILE_INDEX_MANAGER' });
    }
});
const initFileIndexManager = () => {
    const WAIT_TIME_ACTION = 2000;
    let scheduler;
    let streamScheduler;
    let streamProcessor;
    let running = false;
    let shutdown = false;
    const wait = (ms) => {
        return new Promise((resolve) => {
            setTimeout(resolve, ms);
        });
    };
    const fileIndexHandler = () => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext('file_index_manager');
        const settings = yield getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
        const enterpriseEditionEnabled = isNotEmptyField(settings === null || settings === void 0 ? void 0 : settings.enterprise_edition);
        if (enterpriseEditionEnabled) {
            let lock;
            try {
                // Lock the manager
                lock = yield lockResource([FILE_INDEX_MANAGER_KEY], { retryCount: 0 });
                running = true;
                logApp.debug('[OPENCTI-MODULE] Running file index manager');
                const managerConfiguration = yield getManagerConfigurationFromCache(context, SYSTEM_USER, 'FILE_INDEX_MANAGER');
                if (managerConfiguration === null || managerConfiguration === void 0 ? void 0 : managerConfiguration.manager_running) {
                    const indexFromDate = yield getIndexFromDate(context);
                    yield updateManagerConfigurationLastRun(context, SYSTEM_USER, managerConfiguration.id, { last_run_start_date: new Date() });
                    logApp.debug('[OPENCTI-MODULE] Index imported files since', { indexFromDate });
                    yield indexImportedFiles(context, indexFromDate);
                    yield updateManagerConfigurationLastRun(context, SYSTEM_USER, managerConfiguration.id, { last_run_end_date: new Date() });
                    logApp.debug('[OPENCTI-MODULE] End of file index manager processing');
                }
            }
            catch (e) {
                if (e.name === TYPE_LOCK_ERROR) {
                    logApp.debug('[OPENCTI-MODULE] File index manager handler already started by another API');
                }
                else {
                    logApp.error(e, { manager: 'FILE_INDEX_MANAGER' });
                }
            }
            finally {
                running = false;
                if (lock)
                    yield lock.unlock();
            }
        }
    });
    const fileIndexStreamHandler = () => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext('file_index_manager');
        const settings = yield getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
        const enterpriseEditionEnabled = isNotEmptyField(settings === null || settings === void 0 ? void 0 : settings.enterprise_edition);
        if (enterpriseEditionEnabled) {
            let lock;
            try {
                // Lock the manager
                lock = yield lockResource([FILE_INDEX_MANAGER_STREAM_KEY], { retryCount: 0 });
                running = true;
                logApp.info('[OPENCTI-MODULE] Running file index manager stream handler');
                streamProcessor = createStreamProcessor(SYSTEM_USER, 'File index manager', handleStreamEvents);
                yield streamProcessor.start('live');
                while (!shutdown && streamProcessor.running()) {
                    lock.signal.throwIfAborted();
                    yield wait(WAIT_TIME_ACTION);
                }
                logApp.info('[OPENCTI-MODULE] End of file index manager stream handler');
            }
            catch (e) {
                if (e.name === TYPE_LOCK_ERROR) {
                    logApp.debug('[OPENCTI-MODULE] File index manager stream handler already started by another API');
                }
                else {
                    logApp.error(e, { manager: 'FILE_INDEX_MANAGER' });
                }
            }
            finally {
                if (streamProcessor)
                    yield streamProcessor.shutdown();
                if (lock)
                    yield lock.unlock();
            }
        }
    });
    return {
        start: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Starting file index manager');
            scheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                yield fileIndexHandler();
            }), SCHEDULE_TIME);
            // stream to index updates on entities
            streamScheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                yield fileIndexStreamHandler();
            }), STREAM_SCHEDULE_TIME);
        }),
        status: (settings) => {
            return {
                id: 'FILE_INDEX_MANAGER',
                enable: ENABLED_FILE_INDEX_MANAGER && isNotEmptyField(settings === null || settings === void 0 ? void 0 : settings.enterprise_edition),
                running,
                warning: !isAttachmentProcessorEnabled(),
            };
        },
        shutdown: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Stopping file index manager');
            shutdown = true;
            if (scheduler)
                yield clearIntervalAsync(scheduler);
            if (streamScheduler)
                yield clearIntervalAsync(streamScheduler);
            return true;
        }),
    };
};
const fileIndexManager = initFileIndexManager();
export default fileIndexManager;
