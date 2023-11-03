import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { Promise as BluePromise } from 'bluebird';
import moment from 'moment';
import * as R from 'ramda';
import type { BasicStoreSettings } from '../types/settings';
import { EVENT_TYPE_UPDATE, isNotEmptyField, waitInSec } from '../database/utils';
import conf, { ENABLED_FILE_INDEX_MANAGER, logApp } from '../config/conf';
import {
  createStreamProcessor,
  lockResource,
  type StreamProcessor,
} from '../database/redis';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import {
  elIndexFiles,
  elLoadById,
  elSearchFiles,
  elUpdateFilesWithEntityRestrictions,
  isAttachmentProcessorEnabled,
} from '../database/engine';
import { fileListingForIndexing, getFileContent } from '../database/file-storage';
import type { AuthContext } from '../types/user';
import { generateInternalId } from '../schema/identifier';
import { TYPE_LOCK_ERROR } from '../config/errors';
import type { SseEvent, StreamDataEvent, UpdateEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import {
  getManagerConfigurationFromCache,
  updateManagerConfigurationLastRun
} from '../modules/managerConfiguration/managerConfiguration-domain';

const FILE_INDEX_MANAGER_KEY = conf.get('file_index_manager:lock_key');
const SCHEDULE_TIME = conf.get('file_index_manager:interval') || 300000; // 5 minutes
const STREAM_SCHEDULE_TIME = 10000;
const FILE_INDEX_MANAGER_STREAM_KEY = conf.get('file_index_manager:stream_lock_key');

// configuration that will be handled in ManagerConfiguration in MVP2
const defaultMimeTypes = ['application/pdf', 'text/plain', 'text/csv', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];
const ACCEPT_MIME_TYPES: string[] = conf.get('file_index_manager:accept_mime_types') || defaultMimeTypes;
const MAX_FILE_SIZE: number = conf.get('file_index_manager:max_file_size') || 5242880; // 5 mb
const INCLUDE_GLOBAL_FILES: boolean = conf.get('file_index_manager:include_global_files') || false;

const loadFilesToIndex = async (file: { id: string, internalId: string, entityId: string | null, name: string, uploaded_at: Date | undefined }) => {
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

const indexImportedFiles = async (
  context: AuthContext,
  fromDate: Date | null = null,
  path = 'import/',
  includeGlobalFiles = INCLUDE_GLOBAL_FILES,
  maxFileSize = MAX_FILE_SIZE,
  mimeTypes = ACCEPT_MIME_TYPES,
) => {
  const excludedPaths = includeGlobalFiles ? ['import/pending/'] : ['import/pending/', 'import/global/'];
  const fileListingOpts = { modifiedSince: fromDate, excludedPaths, mimeTypes, maxFileSize };
  const allFiles: { id: string; metaData: { entity_id: string; }; name: string; lastModified: Date; }[] = await fileListingForIndexing(context, SYSTEM_USER, path, fileListingOpts);
  if (allFiles.length === 0) {
    return;
  }
  const filesBulk = R.splitEvery(20, allFiles);
  for (let index = 0; index < filesBulk.length; index += 1) {
    const managerConfiguration = await getManagerConfigurationFromCache(context, SYSTEM_USER, 'FILE_INDEX_MANAGER');
    if (managerConfiguration?.manager_running) {
      const files = filesBulk[index];
      // search documents by file id (to update if already indexed)
      const searchOptions = {
        first: files.length,
        connectionFormat: false,
        highlight: false,
        fileIds: files.map((f) => f.id),
        fields: ['internal_id', 'file_id'],
      };
      const existingFiles = await elSearchFiles(context, SYSTEM_USER, searchOptions);
      const filesToLoad = files.map((file) => {
        const existingFile = existingFiles.find((e: { file_id: string, internal_id: string }) => e.file_id === file.id);
        const internalId = existingFile ? existingFile.internal_id : generateInternalId();
        const entityId = file.metaData.entity_id;
        return {
          id: file.id,
          internalId,
          entityId,
          name: file.name,
          uploaded_at: file.lastModified,
        };
      });
      const filesToIndex = await BluePromise.map(filesToLoad, loadFilesToIndex, { concurrency: 5 });
      // index all files one by one
      await elIndexFiles(context, SYSTEM_USER, filesToIndex);
      await waitInSec(1);
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
        const stixFiles = stix.extensions[STIX_EXT_OCTI].files;
        // test if markings or organization sharing have been updated
        const isDataRestrictionsUpdate = updateEvent.context?.patch && updateEvent.context.patch
          .map((op) => op.path && (op.path.includes('granted_refs') || op.path.includes('object_marking_refs')));
        if (stixFiles?.length > 0 && isDataRestrictionsUpdate) {
          // update all indexed files for this entity
          const entity = await elLoadById(context, SYSTEM_USER, entityId);
          await elUpdateFilesWithEntityRestrictions(entity);
        }
      }
    }
  } catch (e) {
    logApp.error('[OPENCTI-MODULE] Error executing file index manager stream handler', { error: e });
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
    const enterpriseEditionEnabled = isNotEmptyField(settings?.enterprise_edition);
    if (enterpriseEditionEnabled) {
      let lock;
      try {
        // Lock the manager
        lock = await lockResource([FILE_INDEX_MANAGER_KEY], { retryCount: 0 });
        running = true;
        logApp.debug('[OPENCTI-MODULE] Running file index manager');
        const managerConfiguration = await getManagerConfigurationFromCache(context, SYSTEM_USER, 'FILE_INDEX_MANAGER');
        if (managerConfiguration?.manager_running) {
          const startDate = new Date();
          const searchOptions = {
            first: 1,
            connectionFormat: false,
            highlight: false,
            orderBy: 'uploaded_at',
            orderMode: 'desc',
          };
          const lastIndexedFiles = await elSearchFiles(context, SYSTEM_USER, searchOptions);
          const lastIndexedFile = lastIndexedFiles?.length > 0 ? lastIndexedFiles[0] : null;
          const indexFromDate = lastIndexedFile ? moment(lastIndexedFile.uploaded_at).toDate() : null;
          logApp.debug('[OPENCTI-MODULE] Index imported files since', { indexFromDate });
          await indexImportedFiles(context, indexFromDate);
          const endDate = new Date();
          await updateManagerConfigurationLastRun(context, SYSTEM_USER, managerConfiguration.id, { last_run_start_date: startDate, last_run_end_date: endDate });
          logApp.debug('[OPENCTI-MODULE] End of file index manager processing');
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
    const enterpriseEditionEnabled = isNotEmptyField(settings?.enterprise_edition);
    if (enterpriseEditionEnabled) {
      let lock;
      try {
        // Lock the manager
        lock = await lockResource([FILE_INDEX_MANAGER_STREAM_KEY], { retryCount: 0 });
        running = true;
        logApp.info('[OPENCTI-MODULE] Running file index manager stream handler');
        streamProcessor = createStreamProcessor(SYSTEM_USER, 'File index manager', handleStreamEvents);
        await streamProcessor.start('live');
        while (!shutdown && streamProcessor.running()) {
          await wait(WAIT_TIME_ACTION);
        }
        logApp.info('[OPENCTI-MODULE] End of file index manager stream handler');
      } catch (e: any) {
        if (e.name === TYPE_LOCK_ERROR) {
          logApp.debug('[OPENCTI-MODULE] File index manager stream handler already started by another API');
        } else {
          logApp.error('[OPENCTI-MODULE] File index manager stream handler failed to start', { error: e });
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
        enable: ENABLED_FILE_INDEX_MANAGER && isNotEmptyField(settings?.enterprise_edition),
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
