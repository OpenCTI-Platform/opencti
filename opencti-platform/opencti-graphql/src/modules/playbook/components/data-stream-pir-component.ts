import type { JSONSchemaType } from 'ajv';
import type { PlaybookComponent } from '../playbook-types';

export interface PirStreamConfiguration {
  create: boolean;
  create_rel: boolean;
  update: boolean;
  delete: boolean;
  inPirFilters: { value: string }[];
  filters: string;
}

// The configuration is stored as free JSON and never validated against the schema,
// so inPirFilters may be missing, null, '' (untouched form field), a single option or bare ids.
export const normalizeInPirFilters = (inPirFilters: unknown): { value: string }[] => {
  if (inPirFilters === null || inPirFilters === undefined || inPirFilters === '') return [];
  const list: unknown[] = Array.isArray(inPirFilters) ? inPirFilters : [inPirFilters];
  return list.flatMap((item) => {
    if (typeof item === 'string') return item ? [{ value: item }] : [];
    const value = (item as { value?: unknown } | null)?.value;
    return typeof value === 'string' && value ? [{ value }] : [];
  });
};

const PLAYBOOK_DATA_STREAM_PIR_SCHEMA: JSONSchemaType<PirStreamConfiguration> = {
  type: 'object',
  properties: {
    inPirFilters: {
      type: 'array',
      uniqueItems: true,
      default: [],
      items: { type: 'string', oneOf: [] },
    },
    create: { type: 'boolean', default: true, $ref: 'A new entity enters a selected PIR' },
    delete: { type: 'boolean', default: false, $ref: 'An entity has left a selected PIR' },
    update: { type: 'boolean', default: false, $ref: 'An entity from a selected PIR has been updated' },
    create_rel: { type: 'boolean', default: false, $ref: 'An entity is linked to an entity from a selected PIR' },
    filters: { type: 'string' },
  },
  required: ['create', 'delete', 'update', 'create_rel'],
};

export const PLAYBOOK_DATA_STREAM_PIR: PlaybookComponent<PirStreamConfiguration> = {
  id: 'PLAYBOOK_DATA_STREAM_PIR',
  name: 'Listen PIR events',
  description: 'Listen for updates to your PIR(s)',
  icon: 'in-pir',
  category: 'start_playbook',
  is_entry_point: true,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_DATA_STREAM_PIR_SCHEMA,
  schema: async () => PLAYBOOK_DATA_STREAM_PIR_SCHEMA,
  executor: async ({ bundle }) => {
    return ({ output_port: 'out', bundle, forceBundleTracking: true });
  },
};
