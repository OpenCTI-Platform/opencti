import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../../schema/module';
import { createdAt, creators, updatedAt } from '../../../schema/attribute-definition';
import { objectMarking, objectOrganization } from '../../../schema/stixRefRelationship';
import convertHuntRunToStix from './huntRun-converter';
import { ENTITY_TYPE_HUNT } from '../hunt-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_USER } from '../../../schema/internalObject';
import {
  ENTITY_TYPE_HUNT_RUN,
  HUNT_RUN_MODES,
  HUNT_RUN_STATUSES,
  HUNT_RUN_TRIGGERS,
  HUNT_VERDICT_SOURCES,
  HUNT_VERDICTS,
  type StixHuntRun,
  type StoreEntityHuntRun,
} from './huntRun-types';

const HUNT_RUN_DEFINITION: ModuleDefinition<StoreEntityHuntRun, StixHuntRun> = {
  type: {
    id: 'hunt-run',
    name: ENTITY_TYPE_HUNT_RUN,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_HUNT_RUN]: () => uuidv4(),
    },
  },
  attributes: [
    creators,
    createdAt,
    updatedAt,
    { name: 'hunt_id', label: 'Run hunt', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_HUNT], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hunt_run_status', label: 'Hunt run status', type: 'string', format: 'enum', values: HUNT_RUN_STATUSES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hunt_run_trigger', label: 'Hunt run trigger', type: 'string', format: 'enum', values: HUNT_RUN_TRIGGERS, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hunt_run_mode', label: 'Run mode', type: 'string', format: 'enum', values: HUNT_RUN_MODES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'security_platform_id', label: 'Run security platform', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'connector_id', label: 'Run connector', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'connector_name', label: 'Run connector name', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'work_id', label: 'Run work', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'time_window_start', label: 'Run time window start', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'time_window_end', label: 'Run time window end', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'translated_query', label: 'Translated query', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'query_language', label: 'Query language', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hits_count', label: 'Run hits', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hits_new_count', label: 'Run new hits', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hits_recurring_count', label: 'Run hits seen before', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'hits_identified', label: 'Run hits identified', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'continues_run_id', label: 'Run continued', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'sightings_created_count', label: 'Run sightings created', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'incident_continued', label: 'Run incident continued', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'results_truncated', label: 'Partial results', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'distinct_entities', label: 'Distinct entities', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'evidence_sample', label: 'Evidence sample', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'hits_sample', label: 'Hits sample', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'first_hit_at', label: 'Run first hit date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_hit_at', label: 'Run last hit date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    // Observed Data and observables the platform created from the hits sample, in the knowledge graph
    { name: 'hit_observation_ids', label: 'Run hit observations', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'ioc_results', label: 'Results per value', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'result_ids', label: 'Run results', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'verdict', label: 'Run verdict', type: 'string', format: 'enum', values: HUNT_VERDICTS, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'verdict_source', label: 'Verdict source', type: 'string', format: 'enum', values: HUNT_VERDICT_SOURCES, mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'verdict_rationale', label: 'Verdict rationale', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'hunt_analyst_feedback', label: 'Hunt analyst feedback', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'verdict_proposal', label: 'Proposed verdict', type: 'string', format: 'enum', values: HUNT_VERDICTS, mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'verdict_proposal_confidence', label: 'Proposed verdict confidence', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'verdict_proposal_rationale', label: 'Proposed verdict rationale', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'verdict_proposal_agent', label: 'Proposing agent', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'incident_proposal', label: 'Proposed incident', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'incident_id', label: 'Run incident', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'draft_id', label: 'Run draft', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'aev_inject_id', label: 'OpenAEV inject', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'security_coverage_id', label: 'Run security coverage', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'technique_id', label: 'Validated technique', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'triggered_by', label: 'Run triggered by', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'attempt', label: 'Run attempt', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'retry_of', label: 'Retried run', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'next_retry_at', label: 'Run next retry date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'dispatched_at', label: 'Run dispatch date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    // Set once the message of the run is in the connector queue: a dispatch date without it is a reservation left behind
    { name: 'published_at', label: 'Run publication date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'started_at', label: 'Run start date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'completed_at', label: 'Run completion date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'cost_ms', label: 'Run duration (ms)', type: 'numeric', precision: 'long', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'error_message', label: 'Run error', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'failure_retryable', label: 'Run failure retryable', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hunt_logic_fingerprint', label: 'Run hunt logic fingerprint', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'auto_escalation', label: 'Run automatic escalation', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'unresolved_techniques', label: 'Run techniques not found', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'playbook_id', label: 'Run playbook', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'playbook_execution_id', label: 'Run playbook execution', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'playbook_step_id', label: 'Run playbook step', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'playbook_instance_id', label: 'Run playbook entity', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'playbook_leader', label: 'Run playbook continuation holder', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'playbook_context', label: 'Run playbook continuation', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'playbook_resumed_at', label: 'Run playbook resume date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'evidence_sources', label: 'Run evidence sources', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'last_evidence_at', label: 'Run last evidence date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
  // A hunt cannot be restricted to members (no authorized members on the Hunt type): the markings and organizations
  // of its hunt and security platform are the whole access of a run, enforced on every read of the run
  relationsRefs: [
    objectMarking,
    { ...objectOrganization, isFilterable: false },
  ],
  representative: (stix: StixHuntRun) => {
    return `${stix.hunt_run_trigger} run (${stix.hunt_run_status})`;
  },
  converter_2_1: convertHuntRunToStix,
};

registerDefinition(HUNT_RUN_DEFINITION);
