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
import { constructFinalPirFilters, parsePir } from '../modules/pir/pir-utils';
import { getEntitiesListFromCache } from '../database/cache';
import { createRedisClient, fetchStreamEventsRangeFromEventId } from '../database/redis';
import { updatePir } from '../modules/pir/pir-domain';
import { pushToWorkerForConnector } from '../database/rabbitmq';
import convertEntityPirToStix from '../modules/pir/pir-converter';
import { buildStixBundle } from '../database/stix-2-1-converter';
import conf, { booleanConf } from '../config/conf';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_UPDATE } from '../database/utils';

const PIR_MANAGER_ID = 'PIR_MANAGER';
const PIR_MANAGER_LABEL = 'Pir Manager';
const PIR_MANAGER_CONTEXT = 'pir_manager';

const PIR_MANAGER_INTERVAL = conf.get('pir_manager:interval') ?? 10000;
const PIR_MANAGER_STREAM_BATCH_SIZE = conf.get('pir_manager:stream_batch_size') ?? 7500;
const PIR_MANAGER_LOCK_KEY = conf.get('pir_manager:lock_key');
const PIR_MANAGER_ENABLED = booleanConf('pir_manager:enabled', false);
const PIR_MANAGER_MAX_CONCURRENCY = conf.get('pir_manager:max_concurrency') ?? 5;

const pirFlagElementToQueue = async (
  pir: BasicStoreEntityPir,
  relationshipId: string,
  sourceId: string,
  matchingCriteria: ParsedPirCriterion[],
  relationshipAuthorId?: string,
) => {
  const stixPir = convertEntityPirToStix(pir as StoreEntityPir);
  stixPir.extensions[STIX_EXT_OCTI].opencti_operation = 'pir_flag_element';
  const pirBundle = {
    ...stixPir,
    input: { relationshipId, sourceId, matchingCriteria, relationshipAuthorId },
  };
  const stixPirBundle = buildStixBundle([pirBundle]);
  const jsonBundle = JSON.stringify(stixPirBundle);
  const content = Buffer.from(jsonBundle, 'utf-8').toString('base64');
  const message = {
    type: 'bundle',
    applicant_id: PIR_MANAGER_USER.id,
    update: true,
    content,
  };
  await pushToWorkerForConnector(pir.internal_id, message);
};

const pirUnflagElementFromQueue = async (
  pir: BasicStoreEntityPir,
  relationshipId: string,
  sourceId: string,
) => {
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
    update: true,
    content,
  };
  await pushToWorkerForConnector(pir.internal_id, message);
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
  const { pir_type, pir_criteria, pir_filters } = pir;
  // 1. Check Pir filters (filters that do not count as criteria).
  const pirFinalFilters = constructFinalPirFilters(pir_type, pir_filters);
  const eventMatchesPirFilters = await isStixMatchFilterGroup(context, PIR_MANAGER_USER, data, pirFinalFilters);
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
    for (let i = 0; i < eventsContent.length; i += 1) {
      const event = eventsContent[i];
      const { data } = event;
      const matchingCriteria = await checkEventOnPir(context, event, parsedPir);
      if (matchingCriteria.length > 0) { // the event matches Pir
        const sourceId: string = data.extensions?.[STIX_EXT_OCTI]?.source_ref;
        if (!sourceId) throw FunctionalError(`Cannot flag the source with Pir ${pir.id}, no source id found`);
        const relationshipId: string = data.extensions?.[STIX_EXT_OCTI]?.id;
        if (!relationshipId) throw FunctionalError(`Cannot flag the source with Pir ${pir.id}, no relationship id found`);
        const relationshipAuthorId = data.extensions?.[STIX_EXT_OCTI]?.created_by_ref_id;
        switch (event.type) {
          case EVENT_TYPE_CREATE:
          case EVENT_TYPE_UPDATE:
            await pirFlagElementToQueue(pir, relationshipId, sourceId, matchingCriteria, relationshipAuthorId);
            break;
          case EVENT_TYPE_DELETE:
            await pirUnflagElementFromQueue(pir, relationshipId, sourceId);
            break;
          default: // Nothing to do
        }
      } else { // the event doesn't match the Pir
        const sourcePirRefs = data.extensions?.[STIX_EXT_OCTI]?.source_ref_pir_refs ?? [];
        if (event.type === EVENT_TYPE_UPDATE && sourcePirRefs.length > 0) {
          const sourceId: string = data.extensions?.[STIX_EXT_OCTI]?.source_ref;
          if (!sourceId) throw FunctionalError(`Cannot flag the source with Pir ${pir.id}, no source id found`);
          const relationshipId: string = data.extensions?.[STIX_EXT_OCTI]?.id;
          if (!relationshipId) throw FunctionalError(`Cannot flag the source with Pir ${pir.id}, no relationship id found`);
          await pirUnflagElementFromQueue(pir, relationshipId, sourceId);
        }
      }
    }
  };
};

/**
 * Handler called every {PIR_MANAGER_INTERVAL} and studying a range of stream events.
 */
const pirManagerHandler = async () => {
  const redisClient = await createRedisClient(PIR_MANAGER_LABEL, false);
  try {
    const context = executionContext(PIR_MANAGER_CONTEXT);
    const allPirs = await getEntitiesListFromCache<BasicStoreEntityPir>(context, PIR_MANAGER_USER, ENTITY_TYPE_PIR);

    // Loop through all Pirs by group
    await BluePromise.map(allPirs, async (pir) => {
      // Fetch stream events since last event id caught by the Pir.
      const { lastEventId } = await fetchStreamEventsRangeFromEventId(
        redisClient,
        pir.lastEventId,
        processStreamEventsForPir(context, pir),
        { streamBatchSize: PIR_MANAGER_STREAM_BATCH_SIZE }
      );
      // Update pir last event id.
      if (lastEventId !== pir.lastEventId) {
        await updatePir(context, PIR_MANAGER_USER, pir.id, [{ key: 'lastEventId', value: [lastEventId] }], { auditLogEnabled: false });
      }
    }, { concurrency: PIR_MANAGER_MAX_CONCURRENCY });
  } finally {
    // close redis client connexion
    redisClient.disconnect();
  }
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
  enterpriseEditionOnly: true,
  cronSchedulerHandler: {
    handler: pirManagerHandler,
    interval: PIR_MANAGER_INTERVAL,
    lockKey: PIR_MANAGER_LOCK_KEY,
  }
};

// Automatically register manager on start.
registerManager(PIR_MANAGER_DEFINITION);
