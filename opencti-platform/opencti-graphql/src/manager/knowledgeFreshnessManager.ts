import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { DECAY_MANAGER_USER, executionContext } from '../utils/access';
import { applyKnowledgeDecayRules } from '../modules/provenance/provenance-freshness';
import { addKnowledgeStaleFlaggedCount } from './telemetryManager';
import { PROVENANCE_ENABLED } from '../modules/provenance/provenance-config';

// Freshness is measured from the assertions: without provenance, there is nothing to evaluate
const KNOWLEDGE_FRESHNESS_MANAGER_ENABLED = booleanConf('knowledge_freshness_manager:enabled', true) && PROVENANCE_ENABLED;
const KNOWLEDGE_FRESHNESS_MANAGER_KEY = conf.get('knowledge_freshness_manager:lock_key') || 'knowledge_freshness_manager_lock';
const SCHEDULE_TIME = conf.get('knowledge_freshness_manager:interval') || 3600000; // 1 hour
const BATCH_SIZE = conf.get('knowledge_freshness_manager:batch_size') || 1000;

/**
 * Apply the knowledge decay rules (relationship and entity scopes) to at most batch_size elements
 * that no source re-asserted for the configured number of days. Indicator scores are never touched.
 */
export const knowledgeFreshnessHandler = async () => {
  const context = executionContext('knowledge_freshness_manager');
  const result = await applyKnowledgeDecayRules(context, DECAY_MANAGER_USER, { batchSize: BATCH_SIZE });
  await addKnowledgeStaleFlaggedCount(result.flagged);
  if (result.errors > 0) {
    logApp.error('[OPENCTI-MODULE] Knowledge freshness manager got errors. Please have a look to previous errors.', { ...result });
  } else {
    logApp.debug('[OPENCTI-MODULE] Knowledge freshness manager applied', { ...result });
  }
  return result;
};

const KNOWLEDGE_FRESHNESS_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'KNOWLEDGE_FRESHNESS_MANAGER',
  label: 'Knowledge freshness manager',
  executionContext: 'knowledge_freshness_manager',
  cronSchedulerHandler: {
    handler: async () => {
      await knowledgeFreshnessHandler();
    },
    interval: SCHEDULE_TIME,
    lockKey: KNOWLEDGE_FRESHNESS_MANAGER_KEY,
  },
  enabledByConfig: KNOWLEDGE_FRESHNESS_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(KNOWLEDGE_FRESHNESS_MANAGER_DEFINITION);
