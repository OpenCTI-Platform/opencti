import { redisGetConnectorStatus, redisGetWork } from '../../database/redis';
import conf, { ENABLED_CONNECTOR_MANAGER, logApp } from '../../config/conf';
import { elList, elUpdate } from '../../database/engine';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { READ_INDEX_HISTORY } from '../../database/utils';
import { now } from '../../utils/format';
import { deleteWorksRaw } from '../../domain/work';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import type { AuthContext } from '../../types/user';
import type { Work } from '../../types/work';
import type { BasicStoreEntityConnector } from './connector-types';
import { connectors } from './connector-domain';
import { registerManager, type ManagerDefinition } from '../../manager/managerModule';

const CONNECTOR_MANAGER_ID = 'CONNECTOR_MANAGER';
const CONNECTOR_MANAGER_CONTEXT = 'connector_manager';

const SCHEDULE_TIME = conf.get('connector_manager:interval') || 60000;
const CONNECTOR_MANAGER_KEY = conf.get('connector_manager:lock_key') || 'connector_manager_lock';
const CONNECTOR_WORK_RANGE = conf.get('connector_manager:works_day_range') || 7;
const BATCH_SIZE = conf.get('connector_manager:batch_size') || 10000;

const closeOldWorks = async (context: AuthContext, connector: BasicStoreEntityConnector) => {
  const status = await redisGetConnectorStatus(connector.internal_id);
  if (status) {
    const [,, timestamp] = status.split('_');
    const filters = {
      mode: FilterMode.And,
      filters: [
        { key: ['connector_id'], values: [connector.internal_id] },
        { key: ['status'], values: ['wait', 'progress'] },
        { key: ['timestamp'], values: [timestamp], operator: FilterOperator.Lt },
      ],
      filterGroups: [],
    };
    const queryCallback = async (elements: Work[]) => {
      for (let i = 0; i < elements.length; i += 1) {
        const element = elements[i];
        try {
          const currentWorkStatus = await redisGetWork(element.internal_id);
          if (currentWorkStatus) {
            const params = { completed_time: now(), completed_number: parseInt(currentWorkStatus.import_processed_number, 10) };
            const sourceScript = `ctx._source['status'] = "complete";
                ctx._source['completed_time'] = params.completed_time;
                ctx._source['completed_number'] = params.completed_number;`;
            await elUpdate(context, element._index, element.internal_id, {
              script: {
                source: sourceScript,
                lang: 'painless',
                params,
              },
            });
            logApp.info('Work completed by force due to age', { workId: element.internal_id });
          }
        } catch (e) {
          logApp.error('[OPENCTI-MODULE] Connector manager error processing work closing', { cause: e });
        }
      }
      return undefined;
    };
    await elList<Work>(context, SYSTEM_USER, [READ_INDEX_HISTORY], {
      filters,
      noFiltersChecking: true,
      types: ['Work'],
      orderBy: 'timestamp',
      baseData: true,
      baseFields: ['internal_id', 'timestamp'],
      maxSize: BATCH_SIZE,
      callback: queryCallback,
    });
  }
};

export const deleteCompletedWorks = async (context: AuthContext, connector: BasicStoreEntityConnector) => {
  const filters = {
    mode: FilterMode.And,
    filters: [
      { key: ['connector_id'], values: [connector.internal_id] },
      { key: ['status'], values: ['complete'] },
      { key: ['completed_time'], values: [`now-${CONNECTOR_WORK_RANGE}d/d`], operator: FilterOperator.Lte },
    ],
    filterGroups: [],
  };
  const queryCallback = async (elements: Work[]) => {
    const message = `[WORKS] Deleting ${elements.length} works for ${connector.name}`;
    logApp.info(message);
    await deleteWorksRaw(context, elements);
    return undefined;
  };
  await elList<Work>(context, SYSTEM_USER, [READ_INDEX_HISTORY], {
    filters,
    types: ['Work'],
    orderBy: 'timestamp',
    noFiltersChecking: true,
    baseData: true,
    baseFields: ['internal_id'],
    maxSize: BATCH_SIZE,
    callback: queryCallback,
  });
};

const connectorHandler = async (lock: { signal: AbortSignal }) => {
  const context = executionContext(CONNECTOR_MANAGER_CONTEXT);
  const platformConnectors = await connectors(context, SYSTEM_USER) as BasicStoreEntityConnector[];
  for (let index = 0; index < platformConnectors.length; index += 1) {
    lock.signal.throwIfAborted();
    const platformConnector = platformConnectors[index];
    await closeOldWorks(context, platformConnector);
    await deleteCompletedWorks(context, platformConnector);
  }
};

const CONNECTOR_MANAGER_DEFINITION: ManagerDefinition = {
  id: CONNECTOR_MANAGER_ID,
  label: 'Connector manager',
  executionContext: CONNECTOR_MANAGER_CONTEXT,
  cronSchedulerHandler: {
    handler: connectorHandler,
    interval: SCHEDULE_TIME,
    lockKey: CONNECTOR_MANAGER_KEY,
    lockInHandlerParams: true,
  },
  enabledByConfig: ENABLED_CONNECTOR_MANAGER,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(CONNECTOR_MANAGER_DEFINITION);
