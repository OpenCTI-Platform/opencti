// eslint-disable-next-line import/no-extraneous-dependencies
import EventSource from 'eventsource';
import axios from 'axios';
import conf, { logApp } from '../config/conf';
import { createRelation, deleteElementById, listEntities, loadById } from '../database/middleware';
import { SYSTEM_USER } from '../utils/access';
import { buildInputDataFromStix } from '../database/stix';
import { sleep } from '../../tests/utils/testQuery';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { UnsupportedError } from '../config/errors';
import { addStixCyberObservable } from '../domain/stixCyberObservable';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { addStixSightingRelationship } from '../domain/stixSightingRelationship';
import { addLabel } from '../domain/label';
import { addExternalReference } from '../domain/externalReference';
import { addKillChainPhase } from '../domain/killChainPhase';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION,
  isStixMetaObject,
} from '../schema/stixMetaObject';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
  isStixDomainObject,
} from '../schema/stixDomainObject';
import { addCampaign } from '../domain/campaign';
import { addCity } from '../domain/city';
import { addCountry } from '../domain/country';
import { addIncident } from '../domain/incident';
import { addIndicator } from '../domain/indicator';
import { addIntrusionSet } from '../domain/intrusionSet';
import { addMalware } from '../domain/malware';
import { addMarkingDefinition } from '../domain/markingDefinition';
import { addNote } from '../domain/note';
import { addObservedData } from '../domain/observedData';
import { addOpinion } from '../domain/opinion';
import { addAttackPattern } from '../domain/attackPattern';
import { addReport } from '../domain/report';
import { addCourseOfAction } from '../domain/courseOfAction';
import { addIndividual } from '../domain/individual';
import { addOrganization } from '../domain/organization';
import { addSector } from '../domain/sector';
import { addSystem } from '../domain/system';
import { addInfrastructure } from '../domain/infrastructure';
import { addRegion } from '../domain/region';
import { addPosition } from '../domain/position';
import { addThreatActor } from '../domain/threatActor';
import { addTool } from '../domain/tool';
import { addVulnerability } from '../domain/vulnerability';
import Queue from '../utils/queue';
import { lockResource } from '../database/redis';
import { ENTITY_TYPE_SYNC } from '../schema/internalObject';
import { createSyncHttpUri, httpBase, patchSync } from '../domain/connector';

const SYNC_MANAGER_KEY = conf.get('sync_manager:lock_key') || 'sync_manager_lock';

const syncManagerInstance = (syncId) => {
  const STATE_UPDATE_SIZE = 100;
  const MIN_QUEUE_SIZE = 100;
  const MAX_QUEUE_SIZE = 500;
  const lDelay = 10;
  const hDelay = 1000;
  // Variables
  let connectionId = null;
  let eventsQueue;
  let eventSource;
  let run = true;
  const startStreamListening = async () => {
    eventsQueue = new Queue();
    const sync = await loadById(SYSTEM_USER, syncId, ENTITY_TYPE_SYNC);
    const { token } = sync;
    const eventSourceUri = createSyncHttpUri(sync);
    logApp.info(`[SYNC] Starting sync manager for ${syncId} (${eventSourceUri})`);
    eventSource = new EventSource(eventSourceUri, { headers: { authorization: `Bearer ${token}` } });
    eventSource.on('create', (d) => {
      eventsQueue.enqueue(d);
    });
    eventSource.on('delete', (d) => {
      eventsQueue.enqueue(d);
    });
    eventSource.on('connected', (d) => {
      connectionId = JSON.parse(d.data).connectionId;
    });
    return sync;
  };
  const manageBackPressure = async ({ uri, token }, currentDelay) => {
    if (connectionId) {
      const connectionManagement = `${httpBase(uri)}stream/connection/${connectionId}`;
      const config = { headers: { authorization: `Bearer ${token}` } };
      if (currentDelay === lDelay && eventsQueue.getLength() > MAX_QUEUE_SIZE) {
        await axios.post(connectionManagement, { delay: hDelay }, config);
        logApp.info(`Connection setup to use ${hDelay} delay`);
        return hDelay;
      }
      if (currentDelay === hDelay && eventsQueue.getLength() < MIN_QUEUE_SIZE) {
        await axios.post(connectionManagement, { delay: lDelay }, config);
        logApp.info(`Connection setup to use ${lDelay} delay`);
        return lDelay;
      }
    }
    return currentDelay;
  };
  const handleDeleteEvent = async (data) => {
    const { type } = buildInputDataFromStix(data);
    logApp.info(`[SYNC] Deleting element ${type} ${data.id}`);
    await deleteElementById(SYSTEM_USER, data.id, type);
  };
  const handleCreateEvent = async (data) => {
    const { type, input } = buildInputDataFromStix(data);
    // Then create the elements
    if (isStixCoreRelationship(type)) {
      logApp.info(`[SYNC] Creating relation ${input.relationship_type} ${input.fromId}/${input.toId}`);
      await createRelation(SYSTEM_USER, input);
    } else if (isStixSightingRelationship(type)) {
      logApp.info(`[SYNC] Creating sighting ${input.fromId}/${input.toId}`);
      await addStixSightingRelationship(SYSTEM_USER, { ...input, relationship_type: input.type });
    } else if (isStixDomainObject(type) || isStixMetaObject(type)) {
      logApp.info(`[SYNC] Creating entity ${type} ${input.stix_id}`);
      // Stix domains
      if (type === ENTITY_TYPE_ATTACK_PATTERN) {
        await addAttackPattern(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_CAMPAIGN) {
        await addCampaign(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_CONTAINER_NOTE) {
        await addNote(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
        await addObservedData(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_CONTAINER_OPINION) {
        await addOpinion(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_CONTAINER_REPORT) {
        await addReport(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_COURSE_OF_ACTION) {
        await addCourseOfAction(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_IDENTITY_INDIVIDUAL) {
        await addIndividual(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_IDENTITY_ORGANIZATION) {
        await addOrganization(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_IDENTITY_SECTOR) {
        await addSector(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_IDENTITY_SYSTEM) {
        await addSystem(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_INDICATOR) {
        await addIndicator(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_INFRASTRUCTURE) {
        await addInfrastructure(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_INTRUSION_SET) {
        await addIntrusionSet(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_LOCATION_CITY) {
        await addCity(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_LOCATION_COUNTRY) {
        await addCountry(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_LOCATION_REGION) {
        await addRegion(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_LOCATION_POSITION) {
        await addPosition(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_MALWARE) {
        await addMalware(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_THREAT_ACTOR) {
        await addThreatActor(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_TOOL) {
        await addTool(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_VULNERABILITY) {
        await addVulnerability(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_INCIDENT) {
        await addIncident(SYSTEM_USER, input);
      }
      // Stix meta
      else if (type === ENTITY_TYPE_LABEL) {
        await addLabel(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_EXTERNAL_REFERENCE) {
        await addExternalReference(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_KILL_CHAIN_PHASE) {
        await addKillChainPhase(SYSTEM_USER, input);
      } else if (type === ENTITY_TYPE_MARKING_DEFINITION) {
        await addMarkingDefinition(SYSTEM_USER, input);
      } else {
        // await createEntity(SYSTEM_USER, input, type);
        throw UnsupportedError(`${type} not handle by synchronizer`);
      }
    } else if (isStixCyberObservable(type)) {
      logApp.info(`[SYNC] Creating cyber observable ${type} ${input.stix_id}`);
      await addStixCyberObservable(SYSTEM_USER, input);
    } else {
      throw UnsupportedError(`${type} not handle by synchronizer`);
    }
  };
  return {
    stop: () => {
      logApp.info(`[SYNC] Stopping sync manager for ${syncId}`);
      run = false;
      eventSource.close();
      eventsQueue = null;
    },
    start: async () => {
      run = true;
      const sync = await startStreamListening();
      let currentDelay = lDelay;
      let eventCount = 0;
      while (run) {
        const event = eventsQueue.dequeue();
        if (event) {
          try {
            currentDelay = manageBackPressure(sync, currentDelay);
            const { type: eventType } = event;
            const { data } = JSON.parse(event.data);
            if (eventType === 'delete') {
              await handleDeleteEvent(data);
            }
            if (eventType === 'create') {
              await handleCreateEvent(data);
            }
            // Update the current state
            if (eventCount > STATE_UPDATE_SIZE) {
              await patchSync(SYSTEM_USER, syncId, { current_state: data.updated_at });
              eventCount = 0;
            }
            eventCount += 1;
          } catch (e) {
            logApp.error('[SYNC] Error processing event', { error: e });
          }
        }
        await sleep(10);
      }
    },
    isRunning: () => run,
  };
};

const initSyncManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let processingLoopPromise;
  let syncListening = true;
  const syncManagers = new Map();
  const processStep = async () => {
    // Get syncs definition
    const syncs = await listEntities(SYSTEM_USER, [ENTITY_TYPE_SYNC], { connectionFormat: false });
    for (let index = 0; index < syncs.length; index += 1) {
      // eslint-disable-next-line prettier/prettier
      const { id, running } = syncs[index];
      const syncInstance = syncManagers.get(id);
      if (syncInstance) {
        // Sync already exist
        if (running && !syncInstance.isRunning()) {
          syncInstance.start();
        }
        if (!running && syncInstance.isRunning()) {
          syncInstance.stop();
        }
      } else if (running) {
        // Sync is not currently running but it should be
        const manager = syncManagerInstance(id);
        syncManagers.set(id, manager);
        // noinspection ES6MissingAwait
        manager.start();
      }
    }
  };
  const processingLoop = async () => {
    let lock;
    try {
      logApp.debug('[OPENCTI] Running sync manager');
      lock = await lockResource([SYNC_MANAGER_KEY]);
      while (syncListening) {
        await processStep();
        await sleep(WAIT_TIME_ACTION);
      }
    } catch (e) {
      // We dont care about failing to get the lock.
      logApp.info('[OPENCTI] Sync manager already in progress by another API');
    } finally {
      logApp.debug('[OPENCTI] Sync manager done');
      if (lock) await lock.unlock();
    }
  };
  return {
    start: async () => {
      processingLoopPromise = processingLoop();
    },
    shutdown: async () => {
      syncListening = false;
      // eslint-disable-next-line no-restricted-syntax
      for (const syncManager of syncManagers.values()) {
        if (syncManager.isRunning()) {
          await syncManager.stop();
        }
      }
      if (processingLoopPromise) {
        await processingLoopPromise;
      }
    },
  };
};
const syncManager = initSyncManager();

export default syncManager;
