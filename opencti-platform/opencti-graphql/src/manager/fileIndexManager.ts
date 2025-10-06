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

import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { Promise as BluePromise } from 'bluebird';
import * as R from 'ramda';
import type { BasicStoreSettings } from '../types/settings';
import { EVENT_TYPE_UPDATE, isEmptyField, waitInSec } from '../database/utils';
import conf, { ENABLED_FILE_INDEX_MANAGER, logApp } from '../config/conf';
import { createStreamProcessor, type StreamProcessor, } from '../database/redis';
import { lockResources } from '../lock/master-lock';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { isAttachmentProcessorEnabled, } from '../database/engine';
import { elIndexFiles, elUpdateFilesWithEntityRestrictions } from '../database/file-search';
import { getFileContent } from '../database/raw-file-storage';
import type { AuthContext } from '../types/user';
import { generateFileIndexId } from '../schema/identifier';
import { TYPE_LOCK_ERROR } from '../config/errors';
import type { SseEvent, StreamDataEvent, UpdateEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { getManagerConfigurationFromCache, updateManagerConfigurationLastRun } from '../modules/managerConfiguration/managerConfiguration-domain';
import { allFilesForPaths, getIndexFromDate } from '../modules/internal/document/document-domain';
import { buildOptionsFromFileManager } from '../domain/file';
import { internalLoadById } from '../database/middleware-loader';

const FILE_INDEX_MANAGER_KEY = conf.get('file_index_manager:lock_key');
const SCHEDULE_TIME = conf.get('file_index_manager:interval') || 60000; // 1 minute
const STREAM_SCHEDULE_TIME = 10000;
const FILE_INDEX_MANAGER_STREAM_KEY = conf.get('file_index_manager:stream_lock_key');

interface FileToIndexObject {
  id: string;
  internalId: string;
  entityId?: string | null;
  name: string;
  uploaded_at: Date | undefined;
}

const loadFilesToIndex = async (file: FileToIndexObject) => {
  const content = await getFileContent(file.id, 'base64');
  return {
    internal_id: file.internalId,
    file_id: file.id,
    file_data: content,
    entity_id: file.entityId,
    name: file.name,
    uploaded_at: file.uploaded_at,
  };
};

export const indexImportedFiles = async (context: AuthContext, indexFromDate: string | null) => {
  const fileOptions = await buildOptionsFromFileManager(context);
  if (isEmptyField(fileOptions.opts.prefixMimeTypes)) {
    return; // no mimetype prefix selected, should return 0 files
  }
  const opts = { ...fileOptions.opts, modifiedSince: indexFromDate };
  const allFiles = await allFilesForPaths(context, SYSTEM_USER, fileOptions.paths ?? [], opts);

  if (allFiles.length === 0) {
    return;
  }
  const filesBulk = R.splitEvery(20, allFiles);
  for (let index = 0; index < filesBulk.length; index += 1) {
    try {
      const managerConfiguration = await getManagerConfigurationFromCache(context, SYSTEM_USER, 'FILE_INDEX_MANAGER');
      if (managerConfiguration?.manager_running) {
        const filesToLoad: FileToIndexObject[] = filesBulk[index].map((file) => {
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
        const filesToIndex = await BluePromise.map(filesToLoad, loadFilesToIndex, { concurrency: 5 })
          .catch((error) => logApp.error('[OPENCTI-MODULE] Index manager indexing error', { cause: error, manager: 'FILE_INDEX_MANAGER' }));

        // index all files one by one
        await elIndexFiles(context, SYSTEM_USER, filesToIndex);
        await waitInSec(1);
      }
    } catch (e) {
      // if one file processing raise an exception, we log and skip the bulk.
      logApp.error('[OPENCTI-MODULE] File index manager handling error', { cause: e, manager: 'FILE_INDEX_MANAGER' });
    }
  }
};

const handleStreamEvents = async (streamEvents: Array<SseEvent<StreamDataEvent>>) => {
  try {
    if (streamEvents.length === 0) {
      return;
    }
    const context = executionContext('file_index_manager');
    for (let index = 0; index < streamEvents.length; index += 1) {
      const event = streamEvents[index];
      if (event.data.type === EVENT_TYPE_UPDATE) {
        const updateEvent: UpdateEvent = event.data as UpdateEvent;
        const stix = updateEvent.data;
        const entityId = stix.extensions[STIX_EXT_OCTI].id;
        const entityType = stix.extensions[STIX_EXT_OCTI].type;
        const stixFiles = stix.extensions[STIX_EXT_OCTI].files;
        // test if markings or organization sharing have been updated
        const isDataRestrictionsUpdate = updateEvent.context?.patch && updateEvent.context.patch
          .map((op) => op.path && (op.path.includes('granted_refs') || op.path.includes('object_marking_refs')));
        if (stixFiles?.length > 0 && isDataRestrictionsUpdate) {
          // update all indexed files for this entity
          const entity = await internalLoadById(context, SYSTEM_USER, entityId, { type: entityType });
          await elUpdateFilesWithEntityRestrictions(entity);
        }
      }
    }
  } catch (e) {
    logApp.error('[OPENCTI-MODULE] File index manager handling error', { cause: e, manager: 'FILE_INDEX_MANAGER' });
  }
};

const initFileIndexManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let scheduler: SetIntervalAsyncTimer<[]>;
  let streamScheduler: SetIntervalAsyncTimer<[]>;
  let streamProcessor: StreamProcessor;
  let running = false;
  let shutdown = false;
  const wait = (ms: number) => {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  };
  const fileIndexHandler = async () => {
    const context = executionContext('file_index_manager');
    const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    if (settings.valid_enterprise_edition === true) {
      let lock;
      try {
        // Lock the manager
        lock = await lockResources([FILE_INDEX_MANAGER_KEY], { retryCount: 0 });
        running = true;
        logApp.debug('[OPENCTI-MODULE] Running file index manager');
        const managerConfiguration = await getManagerConfigurationFromCache(context, SYSTEM_USER, 'FILE_INDEX_MANAGER');
        if (managerConfiguration?.manager_running) {
          const indexFromDate = await getIndexFromDate(context);
          await updateManagerConfigurationLastRun(context, SYSTEM_USER, managerConfiguration.id, { last_run_start_date: new Date() });
          logApp.debug('[OPENCTI-MODULE] Index imported files since', { indexFromDate });
          await indexImportedFiles(context, indexFromDate);
          await updateManagerConfigurationLastRun(context, SYSTEM_USER, managerConfiguration.id, { last_run_end_date: new Date() });
          logApp.debug('[OPENCTI-MODULE] End of file index manager processing');
        }
      } catch (e: any) {
        if (e.name === TYPE_LOCK_ERROR) {
          logApp.debug('[OPENCTI-MODULE] File index manager handler already started by another API');
        } else {
          logApp.error('[OPENCTI-MODULE] File index manager handling error', { cause: e, manager: 'FILE_INDEX_MANAGER' });
        }
      } finally {
        running = false;
        if (lock) await lock.unlock();
      }
    }
  };
  const fileIndexStreamHandler = async () => {
    const context = executionContext('file_index_manager');
    const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    if (settings.valid_enterprise_edition === true) {
      let lock;
      try {
        // Lock the manager
        lock = await lockResources([FILE_INDEX_MANAGER_STREAM_KEY], { retryCount: 0 });
        running = true;
        logApp.info('[OPENCTI-MODULE] Running file index manager stream handler');
        streamProcessor = createStreamProcessor(SYSTEM_USER, 'File index manager', handleStreamEvents, { bufferTime: 5000 });
        await streamProcessor.start('live');
        while (!shutdown && streamProcessor.running()) {
          lock.signal.throwIfAborted();
          await wait(WAIT_TIME_ACTION);
        }
        logApp.info('[OPENCTI-MODULE] End of file index manager stream handler');
      } catch (e: any) {
        if (e.name === TYPE_LOCK_ERROR) {
          logApp.debug('[OPENCTI-MODULE] File index manager stream handler already started by another API');
        } else {
          logApp.error('[OPENCTI-MODULE] File index manager handling error', { cause: e, manager: 'FILE_INDEX_MANAGER' });
        }
      } finally {
        if (streamProcessor) await streamProcessor.shutdown();
        if (lock) await lock.unlock();
      }
    }
  };

  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] Starting file index manager');
      scheduler = setIntervalAsync(async () => {
        await fileIndexHandler();
      }, SCHEDULE_TIME);
      // stream to index updates on entities
      streamScheduler = setIntervalAsync(async () => {
        await fileIndexStreamHandler();
      }, STREAM_SCHEDULE_TIME);
    },
    status: (settings?: BasicStoreSettings) => {
      return {
        id: 'FILE_INDEX_MANAGER',
        enable: ENABLED_FILE_INDEX_MANAGER && settings?.valid_enterprise_edition === true,
        running,
        warning: !isAttachmentProcessorEnabled(),
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping file index manager');
      shutdown = true;
      if (scheduler) await clearIntervalAsync(scheduler);
      if (streamScheduler) await clearIntervalAsync(streamScheduler);
      return true;
    },
  };
};

const fileIndexManager = initFileIndexManager();
export default fileIndexManager;
