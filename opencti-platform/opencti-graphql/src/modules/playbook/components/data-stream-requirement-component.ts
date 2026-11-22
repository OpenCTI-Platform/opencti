import type { JSONSchemaType } from 'ajv';
import type { PlaybookComponent } from '../playbook-types';

// Entry point of a playbook on the events of intelligence requirements: an entity enters or leaves a requirement,
// an entity of a requirement is updated or linked. It replaces "Listen PIR events" (PLAYBOOK_DATA_STREAM_PIR):
// the migration 1795318000000 rewrites every playbook that started on a PIR to this entry, the PIR ids of its
// configuration replaced by the ids of the requirements the PIRs became.
export const PLAYBOOK_DATA_STREAM_REQUIREMENT_ID = 'PLAYBOOK_DATA_STREAM_INTELLIGENCE_REQUIREMENT';

export interface RequirementStreamConfiguration {
  create: boolean;
  create_rel: boolean;
  update: boolean;
  delete: boolean;
  requirementFilters: { value: string; label?: string }[];
  filters: string;
}

const PLAYBOOK_DATA_STREAM_REQUIREMENT_SCHEMA: JSONSchemaType<RequirementStreamConfiguration> = {
  type: 'object',
  properties: {
    requirementFilters: {
      type: 'array',
      uniqueItems: true,
      default: [],
      items: { type: 'string', oneOf: [] },
    },
    create: { type: 'boolean', default: true, $ref: 'A new entity enters a selected intelligence requirement' },
    delete: { type: 'boolean', default: false, $ref: 'An entity has left a selected intelligence requirement' },
    update: { type: 'boolean', default: false, $ref: 'An entity from a selected intelligence requirement has been updated' },
    create_rel: { type: 'boolean', default: false, $ref: 'An entity is linked to an entity from a selected intelligence requirement' },
    filters: { type: 'string' },
  },
  required: ['create', 'delete', 'update', 'create_rel'],
};

export const PLAYBOOK_DATA_STREAM_REQUIREMENT: PlaybookComponent<RequirementStreamConfiguration> = {
  id: PLAYBOOK_DATA_STREAM_REQUIREMENT_ID,
  name: 'Listen intelligence requirement events',
  description: 'Listen for updates to your intelligence requirement(s)',
  icon: 'in-pir',
  category: 'start_playbook',
  is_entry_point: true,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_DATA_STREAM_REQUIREMENT_SCHEMA,
  schema: async () => PLAYBOOK_DATA_STREAM_REQUIREMENT_SCHEMA,
  executor: async ({ bundle }) => {
    return ({ output_port: 'out', bundle, forceBundleTracking: true });
  },
};
