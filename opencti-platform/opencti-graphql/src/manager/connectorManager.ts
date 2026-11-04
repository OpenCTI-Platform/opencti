import { redisGetConnectorStatus, redisGetWork } from '../database/redis';
import conf, { ENABLED_CONNECTOR_MANAGER, logApp } from '../config/conf';
import { elList, elUpdate } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { READ_INDEX_HISTORY } from '../database/utils';
import { now } from '../utils/format';
import { deleteWorksRaw, updateProcessedTime } from '../domain/work';
import { FilterMode, FilterOperator } from '../generated/graphql';
import type { AuthContext } from '../types/user';
import type { Work } from '../types/work';
import type { BasicStoreEntityConnector } from '../modules/connector/connector-types';
import { connectors } from '../modules/connector/connector-domain';
import { registerManager, type ManagerDefinition } from './managerModule';
import { abandonedWorkAction } from './workClosing';

const CONNECTOR_MANAGER_ID = 'CONNECTOR_MANAGER';
const CONNECTOR_MANAGER_CONTEXT = 'connector_manager';

const SCHEDULE_TIME = conf.get('connector_manager:interval') || 60000;
const CONNECTOR_MANAGER_KEY = conf.get('connector_manager:lock_key') || 'connector_manager_lock';
const CONNECTOR_WORK_RANGE = conf.get('connector_manager:works_day_range') || 7;
const BATCH_SIZE = conf.get('connector_manager:batch_size') || 10000;

// ADR 0007: a work left open is first released (multipart gate lifted, it completes when its
// objects are all reported); it is forced complete only after this long without progress.
const WORK_STALE_MINUTES = conf.get('connector_manager:work_stale_minutes') ?? 60;

const forceCompleteWork = async (context: AuthContext, element: Work, workState: Record<string, string>, reason: string) => {
  const processed = parseInt(workState.import_processed_number ?? '0', 10) || 0;
  const expected = parseInt(workState.import_expected_number ?? '0', 10) || 0;
  const params = {
    completed_time: now(),
    completed_number: processed,
    expected_number: expected,
    error: `${reason}: ${Math.max(expected - processed, 0)} of ${expected} expected objects never reported`,
    source: 'connector manager',
  };
  let sourceScript = `ctx._source['status'] = "complete";
    ctx._source['completed_time'] = params.completed_time;
    ctx._source['completed_number'] = params.completed_number;
    ctx._source['import_expected_number'] = params.expected_number;`;
  if (expected > processed) {
    sourceScript += 'if (ctx._source.errors.length < 100) { ctx._source.errors.add(["timestamp": params.completed_time, "message": params.error, "source": params.source]); }';
  }
  await elUpdate(context, element._index, element.internal_id, { script: { source: sourceScript, lang: 'painless', params } });
  logApp.info('Work completed by force after inactivity', { workId: element.internal_id, processed, expected });
};

// Close the works of finished runs: the works older than the connector's current one (a newer
// run has started reporting), and every open work of a connector that stopped pinging.
const closeAbandonedWorks = async (context: AuthContext, connector: BasicStoreEntityConnector) => {
  const status = await redisGetConnectorStatus(connector.internal_id);
  const isInactive = !connector.built_in && connector.active === false;
  if (!status && !isInactive) return;
  const reason = isInactive ? 'Closed by the platform: the connector is no longer active' : 'Closed by the platform: a newer run started';
  const filterList = [
    { key: ['connector_id'], values: [connector.internal_id] },
    { key: ['status'], values: ['wait', 'progress'] },
  ];
  if (!isInactive && status) {
    const [,, timestamp] = status.split('_');
    filterList.push({ key: ['timestamp'], values: [timestamp], operator: FilterOperator.Lt } as typeof filterList[number]);
  }
  const filters = { mode: FilterMode.And, filters: filterList, filterGroups: [] };
  const queryCallback = async (elements: Work[]) => {
    for (let i = 0; i < elements.length; i += 1) {
      const element = elements[i];
      try {
        const workState = await redisGetWork(element.internal_id);
        const action = abandonedWorkAction(workState, Date.now(), WORK_STALE_MINUTES);
        if (action === 'release') {
          await updateProcessedTime(context, SYSTEM_USER, element.internal_id, reason);
          logApp.info('Work released by the connector manager', { workId: element.internal_id, reason });
        } else if (action === 'force') {
          await forceCompleteWork(context, element, workState, reason);
        }
      } catch (e) {
        logApp.warn('[OPENCTI-MODULE] Connector manager error processing work closing', { cause: e });
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
    // Release, then force after inactivity, the works of finished runs (ADR 0007)
    await closeAbandonedWorks(context, platformConnector);
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
