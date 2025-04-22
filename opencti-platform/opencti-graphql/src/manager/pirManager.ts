import { type ManagerDefinition, registerManager } from './managerModule';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { FAKE_PIR, type PIR } from '../modules/pir/pir.fake';
import type { DataEvent, SseEvent } from '../types/event';
import { type FilterGroup, FilterMode } from '../generated/graphql';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
import { STIX_TYPE_RELATION } from '../schema/general';

const PIR_MANAGER_ID = 'PIR_MANAGER';
const PIR_MANAGER_LABEL = 'PIR Manager';
const PIR_MANAGER_CONTEXT = 'pir_manager';

const PIR_MANAGER_INTERVAL = 10000; // TODO PIR: use config instead
const PIR_MANAGER_LOCK_KEY = 'pir_manager_lock'; // TODO PIR: use config instead
const PIR_MANAGER_ENABLED = true; // TODO PIR: use config instead

/**
 * Build a filter group containing all criteria and filters of a PIR.
 *
 * @param pir The PIR to build filters.
 * @returns A filter group describing the PIR.
 */
const buildAllPIRFilters = (pir: PIR): FilterGroup => {
  const criteriaFilters: FilterGroup = {
    mode: FilterMode.Or,
    filters: [],
    filterGroups: pir.criteria.map((c) => c.filters)
  };
  return {
    mode: FilterMode.And,
    filters: [],
    filterGroups: [pir.filters, criteriaFilters]
  };
};

/**
 * Handler called every {PIR_MANAGER_INTERVAL} with new events received.
 * @param streamEvents The new events received since last call to the handler.
 */
const pirManagerHandler = async (streamEvents: Array<SseEvent<DataEvent>>) => {
  const allPIR = [FAKE_PIR]; // TODO PIR: fetch real ones from elastic.
  const context = executionContext(PIR_MANAGER_CONTEXT);

  // Keep only events for relationships
  const eventsContent = streamEvents
    .map((e) => e.data)
    .filter((e) => e.data.type === STIX_TYPE_RELATION);

  if (eventsContent.length > 0) {
    console.log('[POC PIR] Investigate events', { eventsContent });
    await Promise.all(allPIR.map(async (pir) => {
      const pirFilters = buildAllPIRFilters(pir);
      await Promise.all(eventsContent.map(async ({ data }) => {
        // TODO PIR: filters id cache
        const isMatching = await isStixMatchFilterGroup(context, SYSTEM_USER, data, pirFilters);
        if (isMatching) {
          console.log('[POC PIR] Matching event', { data });
        }
      }));
    }));
  } else {
    console.log('[POC PIR] Nothing to do, get some rest');
  }
};

// Configuration of the manager.
const PIR_MANAGER_DEFINITION: ManagerDefinition = {
  id: PIR_MANAGER_ID,
  label: PIR_MANAGER_LABEL,
  executionContext: PIR_MANAGER_CONTEXT,
  enabledByConfig: PIR_MANAGER_ENABLED,
  enabled(): boolean {
    return this.enabledByConfig;
  },
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  streamSchedulerHandler: {
    handler: pirManagerHandler,
    streamProcessorStartFrom: () => 'live',
    interval: PIR_MANAGER_INTERVAL,
    lockKey: PIR_MANAGER_LOCK_KEY,
  }
};
// Automatically register manager on start.
registerManager(PIR_MANAGER_DEFINITION);
