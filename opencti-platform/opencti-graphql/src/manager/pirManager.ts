import { Promise as BluePromise } from 'bluebird';
import { type ManagerDefinition, registerManager } from './managerModule';
import { executionContext, PIR_MANAGER_USER } from '../utils/access';
import type { DataEvent, SseEvent } from '../types/event';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
import { STIX_TYPE_RELATION } from '../schema/general';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import type { AuthContext } from '../types/user';
import { FunctionalError } from '../config/errors';
import { type BasicStoreEntityPir, ENTITY_TYPE_PIR, type ParsedPir, type ParsedPirCriterion, type StoreEntityPir } from '../modules/pir/pir-types';
import { parsePir } from '../modules/pir/pir-utils';
import { getEntitiesListFromCache } from '../database/cache';
import { createRedisClient, fetchStreamEventsRange } from '../database/redis';
import { updatePir } from '../modules/pir/pir-domain';
import { pushToWorkerForConnector } from '../database/rabbitmq';
import { connectorIdFromIngestId } from '../domain/connector';
import { createWork } from '../domain/work';
import { ConnectorType } from '../generated/graphql';
import convertEntityPirToStix from '../modules/pir/pir-converter';
import { buildStixBundle } from '../database/stix-2-1-converter';
import conf, { booleanConf, isFeatureEnabled } from '../config/conf';

const PIR_MANAGER_ID = 'PIR_MANAGER';
const PIR_MANAGER_LABEL = 'Pir Manager';
const PIR_MANAGER_CONTEXT = 'pir_manager';

const PIR_MANAGER_INTERVAL = conf.get('pir_manager:interval') ?? 10000;
const PIR_MANAGER_LOCK_KEY = conf.get('pir_manager:lock_key');
const PIR_MANAGER_ENABLED = booleanConf('pir_manager:enabled', false);

const pirFlagElementToQueue = async (
  context: AuthContext,
  pir: BasicStoreEntityPir,
  relationshipId: string,
  sourceId: string,
  matchingCriteria: ParsedPirCriterion[],
) => {
  const connectorId = connectorIdFromIngestId(pir.id);
  const work: any = await createWork(
    context,
    PIR_MANAGER_USER,
    { internal_id: connectorId, connector_type: ConnectorType.InternalIngestionPir },
    `Add dependency ${matchingCriteria} for ${sourceId} in pir ${pir.name}`
  );
  const stixPir = convertEntityPirToStix(pir as StoreEntityPir);
  stixPir.extensions[STIX_EXT_OCTI].opencti_operation = 'pir_flag_element';
  const pirBundle = {
    ...stixPir,
    input: { relationshipId, sourceId, matchingCriteria },
  };
  const stixPirBundle = buildStixBundle([pirBundle]);
  const jsonBundle = JSON.stringify(stixPirBundle);
  const content = Buffer.from(jsonBundle, 'utf-8').toString('base64');
  const message = {
    type: 'bundle',
    applicant_id: PIR_MANAGER_USER.id,
    work_id: work.id,
    update: true,
    content,
  };
  await pushToWorkerForConnector(connectorId, message);
};

const pirUnflagElementFromQueue = async (
  context: AuthContext,
  pir: BasicStoreEntityPir,
  relationshipId: string,
  sourceId: string,
) => {
  const connectorId = connectorIdFromIngestId(pir.id);
  const work: any = await createWork(
    context,
    PIR_MANAGER_USER,
    { internal_id: connectorId, connector_type: ConnectorType.InternalIngestionPir },
    `Remove dependency ${relationshipId} for ${sourceId} in pir ${pir.name}`
  );
  const stixPir = convertEntityPirToStix(pir as StoreEntityPir);
  stixPir.extensions[STIX_EXT_OCTI].opencti_operation = 'pir_unflag_element';
  const pirBundle = {
    ...stixPir,
    input: { relationshipId, sourceId },
  };
  const stixPirBundle = buildStixBundle([pirBundle]);
  const jsonBundle = JSON.stringify(stixPirBundle);
  const content = Buffer.from(jsonBundle, 'utf-8').toString('base64');
  const message = {
    type: 'bundle',
    applicant_id: PIR_MANAGER_USER.id,
    work_id: work.id,
    update: true,
    content,
  };
  await pushToWorkerForConnector(connectorId, message);
};

/**
 * Find the criteria of the PIR that the event matches.
 * Empty array if the event does not match the PIR.
 *
 * @param context To call internal stuff.
 * @param event The event to check.
 * @param pir The PIR to check.
 * @returns Array of matching criteria, if any.
 */
export const checkEventOnPir = async (context: AuthContext, event: SseEvent<any>, pir: ParsedPir) => {
  const { data } = event;
  const { pir_criteria, pir_filters } = pir;
  // 1. Check Pir filters (filters that do not count as criteria).
  const eventMatchesPirFilters = await isStixMatchFilterGroup(context, PIR_MANAGER_USER, data, pir_filters);
  // 2. Check Pir criteria one by one (because we need to know which one matches or not).
  const matchingCriteria: typeof pir_criteria = [];
  if (eventMatchesPirFilters) {
    // eslint-disable-next-line no-restricted-syntax
    for (const pirCriterion of pir_criteria) {
      const isMatch = await isStixMatchFilterGroup(context, PIR_MANAGER_USER, data, pirCriterion.filters);
      if (isMatch) matchingCriteria.push(pirCriterion);
    }
  }
  return matchingCriteria;
};

const processStreamEventsForPir = (context:AuthContext, pir: BasicStoreEntityPir) => {
  const parsedPir = parsePir(pir);

  return async (streamEvents: Array<SseEvent<DataEvent>>) => {
    const eventsContent = streamEvents
      .map((e) => e.data)
      .filter((e) => e.data.type === STIX_TYPE_RELATION);

    // Check every event received to see if it matches the Pir.
    await BluePromise.map(eventsContent, async (event) => {
      const { data } = event;
      const matchingCriteria = await checkEventOnPir(context, event, parsedPir);
      // If the event matches Pir, do the right thing depending on the type of event.
      if (matchingCriteria.length > 0) {
        const sourceId: string = data.extensions?.[STIX_EXT_OCTI]?.source_ref;
        if (!sourceId) throw FunctionalError(`Cannot flag the source with Pir ${pir.id}, no source id found`);
        const relationshipId: string = data.extensions?.[STIX_EXT_OCTI]?.id;
        if (!relationshipId) throw FunctionalError(`Cannot flag the source with Pir ${pir.id}, no relationship id found`);
        switch (event.type) {
          case 'create':
            // send pirFlagElement to queue
            await pirFlagElementToQueue(context, pir, relationshipId, sourceId, matchingCriteria);
            break;
          case 'delete':
            await pirUnflagElementFromQueue(context, pir, relationshipId, sourceId);
            break;
          default: // Nothing to do. // TODO PIR update logic
        }
      }
    }, { concurrency: 5 });
  };
};

/**
 * Handler called every {PIR_MANAGER_INTERVAL} and studying a range of stream events.
 */
const pirManagerHandler = async () => {
  const redisClient = await createRedisClient(PIR_MANAGER_LABEL, false);
  const context = executionContext(PIR_MANAGER_CONTEXT);
  const allPir = await getEntitiesListFromCache<BasicStoreEntityPir>(context, PIR_MANAGER_USER, ENTITY_TYPE_PIR);

  // Loop through all Pir one by one.
  await BluePromise.map(allPir, async (pir) => {
    // Fetch stream events since last event id caught by the Pir.
    const { lastEventId } = await fetchStreamEventsRange(
      redisClient,
      pir.lastEventId,
      processStreamEventsForPir(context, pir),
      { streamBatchTime: PIR_MANAGER_INTERVAL }
    );
    // Update pir last event id.
    if (lastEventId !== pir.lastEventId) {
      await updatePir(context, PIR_MANAGER_USER, pir.id, [{ key: 'lastEventId', value: [lastEventId] }]);
    }
  }, { concurrency: 5 });
};

// Configuration of the manager.
const PIR_MANAGER_DEFINITION: ManagerDefinition = {
  id: PIR_MANAGER_ID,
  label: PIR_MANAGER_LABEL,
  executionContext: PIR_MANAGER_CONTEXT,
  enabledByConfig: PIR_MANAGER_ENABLED,
  enabled(): boolean {
    return this.enabledByConfig && !!PIR_MANAGER_LOCK_KEY;
  },
  enabledToStart(): boolean {
    return this.enabledByConfig && !!PIR_MANAGER_LOCK_KEY;
  },
  cronSchedulerHandler: {
    handler: pirManagerHandler,
    interval: PIR_MANAGER_INTERVAL,
    lockKey: PIR_MANAGER_LOCK_KEY,
  }
};
// Automatically register manager on start.
if (isFeatureEnabled('Pir')) registerManager(PIR_MANAGER_DEFINITION);
