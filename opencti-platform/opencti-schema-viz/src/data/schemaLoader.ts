import { normalizeSchema } from './normalizeSchema';
import type { NormalizedSchema, RawSchema } from './schemaTypes';

/**
 * Where the raw schema comes from. Today: the static schema.json produced by
 * `yarn generate`. Target: a live GraphQL `__schema` introspection, enriched by
 * an OpenCTI-specific query for what introspection does not expose
 * (stixType, isRefAttribute, STIX compliance of attributes).
 */
export interface SchemaSource {
  load: (signal?: AbortSignal) => Promise<RawSchema>;
}

const isRawSchema = (value: unknown): value is RawSchema => typeof value === 'object'
  && value !== null
  && Array.isArray((value as RawSchema).nodes)
  && Array.isArray((value as RawSchema).edges);

export const staticSchemaSource = (url = `${import.meta.env.BASE_URL}schema.json`): SchemaSource => ({
  load: async (signal) => {
    const response = await fetch(url, { signal });
    if (!response.ok) {
      throw new Error(`Cannot load ${url}: HTTP ${response.status}`);
    }
    const body: unknown = await response.json();
    if (!isRawSchema(body)) {
      throw new Error(`${url} is not a schema file: expected "nodes" and "edges" arrays`);
    }
    return body;
  },
});

export const loadSchema = async (source: SchemaSource = staticSchemaSource(), signal?: AbortSignal): Promise<NormalizedSchema> => {
  return normalizeSchema(await source.load(signal));
};
