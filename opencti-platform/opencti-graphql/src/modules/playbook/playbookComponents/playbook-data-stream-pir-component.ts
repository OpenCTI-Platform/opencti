import type { JSONSchemaType } from 'ajv';
import type { PlaybookComponent } from '../playbook-types';

export interface PirStreamConfiguration {
  create: boolean,
  update: boolean,
  delete: boolean,
  inPirFilters: string,
  filters: string,
}

const PLAYBOOK_DATA_STREAM_PIR_SCHEMA: JSONSchemaType<PirStreamConfiguration> = {
  type: 'object',
  properties: {
    create: { type: 'boolean', default: true },
    update: { type: 'boolean', default: false },
    delete: { type: 'boolean', default: false },
    inPirFilters: { type: 'string' },
    filters: { type: 'string' },
  },
  required: ['create', 'update', 'delete'],
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
