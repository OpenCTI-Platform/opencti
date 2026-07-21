// PoC merge-users #3 - schema-driven dry-run plan builder.
// This module is intentionally read-only: it only DESCRIBES the operations that a
// future merge engine would need to perform, it never writes to Elasticsearch.
import * as fs from 'node:fs';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import type { AttributeDefinition, IdAttribute } from '../schema/attribute-definition';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { READ_DATA_INDICES } from '../database/utils';

export type MergeUserPair = { sourceId: string; targetId: string };

export type MergeOperationComplexity = 'simple' | 'json' | 'graph_rights' | 'runtime';

export type MergeOperation = {
  champ: string;
  type_operation: string;
  index_cible: string;
  complexite: MergeOperationComplexity;
  executable_par_script: boolean;
  commentaire?: string;
};

export type MergeUserPlan = {
  source_id: string;
  target_id: string;
  operations_schema_driven: MergeOperation[];
  operations_hors_schema: MergeOperation[];
};

const isIdAttribute = (attribute: AttributeDefinition): attribute is IdAttribute => attribute.type === 'string' && attribute.format === 'id';

/**
 * Pure filter, extracted so it can be unit tested against an arbitrary list of attributes
 * without touching the live (singleton, write-once) `schemaAttributesDefinition` registry.
 * This is what makes the discovery "schema-driven": no attribute name is hardcoded here,
 * only the generic rule "id-format attribute pointing to a User".
 */
export const filterUserIdAttributes = (attributes: AttributeDefinition[]): IdAttribute[] => {
  return attributes.filter(isIdAttribute).filter((attribute) => attribute.entityTypes?.includes(ENTITY_TYPE_USER));
};

/**
 * Schema-driven discovery of every attribute that can hold a reference to a User.
 * This is the core of the PoC: it relies solely on `schemaAttributesDefinition`, so any
 * new `id` attribute registered with `entityTypes` including ENTITY_TYPE_USER will be
 * picked up automatically, without touching this function.
 */
export const discoverUserIdAttributes = (): IdAttribute[] => {
  return filterUserIdAttributes(schemaAttributesDefinition.getIdAttributes());
};

const buildSchemaDrivenOperations = (): MergeOperation[] => {
  return discoverUserIdAttributes().map((attribute) => {
    // attrRawIds means the id(s) can be buried inside a JSON blob (e.g. object attributes,
    // or string/json attributes storing structured data): a straight string replace is not
    // enough, the value must be parsed first.
    const isComplexJson = attribute.attrRawIds !== undefined;
    return {
      champ: attribute.name,
      type_operation: isComplexJson ? 'rewrite_id_in_json' : 'rewrite_id_attribute',
      index_cible: READ_DATA_INDICES.join(','),
      complexite: isComplexJson ? 'json' : 'simple',
      executable_par_script: true,
      commentaire: isComplexJson
        ? 'Id(s) potentially embedded in a JSON/object value, requires attrRawIds parsing before rewrite'
        : undefined,
    };
  });
};

/**
 * Categories that are NOT discoverable from `schemaAttributesDefinition.getIdAttributes()`
 * because they are not modeled as simple `id`-format attributes (STIX refs, graph
 * relationships materializing rights, or runtime state living outside Elasticsearch).
 * They are enumerated explicitly here and kept in a clearly separated section of the plan.
 */
const buildOutOfSchemaOperations = (): MergeOperation[] => [
  {
    champ: 'created-by',
    type_operation: 'rewrite_stix_ref_relationship',
    index_cible: READ_DATA_INDICES.join(','),
    complexite: 'simple',
    executable_par_script: true,
    commentaire: 'STIX ref relationship, not an id-format attribute',
  },
  {
    champ: 'object-assignee',
    type_operation: 'rewrite_stix_ref_relationship',
    index_cible: READ_DATA_INDICES.join(','),
    complexite: 'simple',
    executable_par_script: true,
    commentaire: 'STIX ref relationship, not an id-format attribute',
  },
  {
    champ: 'object-participant',
    type_operation: 'rewrite_stix_ref_relationship',
    index_cible: READ_DATA_INDICES.join(','),
    complexite: 'simple',
    executable_par_script: true,
    commentaire: 'STIX ref relationship, not an id-format attribute',
  },
  {
    champ: 'member_of / has_role / has_capability / participate_to',
    type_operation: 'merge_or_deduplicate_rights',
    index_cible: READ_DATA_INDICES.join(','),
    complexite: 'graph_rights',
    executable_par_script: false,
    commentaire: 'Graph relationships materialize rights: must be merged/de-duplicated, never blindly rewritten (e.g. avoid duplicate role assignment)',
  },
  {
    champ: 'sessions_tokens_notifications_locks',
    type_operation: 'invalidate_or_migrate_runtime_state',
    index_cible: 'redis',
    complexite: 'runtime',
    executable_par_script: false,
    commentaire: 'Runtime state (Redis sessions, tokens + cache, notifications, locks) lives outside Elasticsearch and is out of this script scope',
  },
];

export const buildMergeUserPlan = (pair: MergeUserPair): MergeUserPlan => ({
  source_id: pair.sourceId,
  target_id: pair.targetId,
  operations_schema_driven: buildSchemaDrivenOperations(),
  operations_hors_schema: buildOutOfSchemaOperations(),
});

/**
 * Minimal CSV parser for the "source_id,target_id" format expected by the batch mode.
 * Kept dependency-free on purpose since the file format is trivial.
 */
export const parseMergeUserCsv = (csvPath: string): MergeUserPair[] => {
  const content = fs.readFileSync(csvPath, 'utf8');
  const lines = content.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length > 0);
  if (lines.length === 0) {
    return [];
  }
  const [header, ...rows] = lines;
  const hasHeader = header.toLowerCase().replace(/\s/g, '') === 'source_id,target_id';
  const dataLines = hasHeader ? rows : lines;
  return dataLines.map((line) => {
    const [sourceId, targetId] = line.split(',').map((value) => value.trim());
    return { sourceId, targetId };
  });
};
