import type { JSONSchemaType } from 'ajv';
import type { PlaybookComponent } from '../playbook-types';

export interface PirStreamConfiguration {
  create: boolean,
  // update: boolean,
  delete: boolean,
  inPirFilters: { value: string }[],
  filters: string,
}

const PLAYBOOK_DATA_STREAM_PIR_SCHEMA: JSONSchemaType<PirStreamConfiguration> = {
  type: 'object',
  properties: {
    inPirFilters: {
      type: 'array',
      uniqueItems: true,
      default: [],
      items: { type: 'string', oneOf: [] }
    },
    create: { type: 'boolean', default: true, $ref: 'A new entity enters a selected PIR' },
    // update: { type: 'boolean', default: false, $ref: 'An entity from a selected PIR has been updated' },
    delete: { type: 'boolean', default: false, $ref: 'An entity has left a selected PIR' },
    filters: { type: 'string' },
  },
  required: ['create', 'delete'],
};

export const PLAYBOOK_DATA_STREAM_PIR: PlaybookComponent<PirStreamConfiguration> = {
  id: 'PLAYBOOK_DATA_STREAM_PIR',
  name: 'Listen PIR events',
  description: 'Listen for all internal PIR events',
  icon: 'in-pir',
  is_entry_point: true,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_DATA_STREAM_PIR_SCHEMA,
  schema: async () => PLAYBOOK_DATA_STREAM_PIR_SCHEMA,
  executor: async ({ bundle }) => {
    return ({ output_port: 'out', bundle, forceBundleTracking: true });
  }
};
