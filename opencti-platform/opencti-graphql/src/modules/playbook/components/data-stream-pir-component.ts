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

// The configuration is stored as free JSON and never validated against the schema, so inPirFilters
// is not guaranteed to be what the form saves: an array of { value } options.
// Only that shape is read, as the resolved filters cache does (cacheManager): a PIR id the cache
// does not resolve would never match "toId" filters, so reading more shapes here would half-work.
const isEmptyInPirFilters = (inPirFilters: unknown) => inPirFilters === null || inPirFilters === undefined
  || (Array.isArray(inPirFilters) && inPirFilters.length === 0);

export const normalizeInPirFilters = (inPirFilters: unknown): { value: string }[] => {
  if (!Array.isArray(inPirFilters)) return [];
  return inPirFilters.flatMap((item) => {
    const value = typeof item === 'object' && item !== null ? (item as { value?: unknown }).value : undefined;
    return typeof value === 'string' && value ? [{ value }] : [];
  });
};

// An empty selection means "any PIR". A selection that was set but yields no PIR id
// must not silently widen to that: callers should match nothing instead.
export const isUnreadableInPirFilters = (inPirFilters: unknown) => {
  return !isEmptyInPirFilters(inPirFilters) && normalizeInPirFilters(inPirFilters).length === 0;
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
