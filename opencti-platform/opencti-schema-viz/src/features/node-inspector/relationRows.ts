import { incomingRelations, outgoingRelations } from '../../data/normalizeSchema';
import type { NormalizedSchema, SchemaRelation, SchemaType } from '../../data/schemaTypes';

export interface RelationRow {
  key: string;
  name: string;
  kind: SchemaRelation['kind'];
  stixStatus: SchemaRelation['stixStatus'];
  relationIds: string[];
  /** Targets for outgoing rows, sources for incoming rows. */
  counterpartIds: string[];
  /** Incoming rows only: the ancestor the relation actually targets, when it is not the type itself. */
  viaTypeId: string | null;
}

export const outgoingRows = (schema: NormalizedSchema, type: SchemaType, includeRefs: boolean): RelationRow[] => outgoingRelations(schema, type.id, includeRefs)
  .map((relation) => ({
    key: relation.id,
    name: relation.name,
    kind: relation.kind,
    stixStatus: relation.stixStatus,
    relationIds: [relation.id],
    counterpartIds: relation.targetTypeIds,
    viaTypeId: null,
  }));

/** Incoming relations grouped by name, including those declared on an ancestor (Indicator based-on Stix-Cyber-Observable applies to IPv4-Addr). */
export const incomingRows = (schema: NormalizedSchema, type: SchemaType, includeRefs: boolean): RelationRow[] => {
  const rows = new Map<string, RelationRow>();
  for (const targetId of [type.id, ...[...type.ancestorIds].reverse()]) {
    for (const relation of incomingRelations(schema, targetId, includeRefs)) {
      const viaTypeId = targetId === type.id ? null : targetId;
      const key = `${relation.name}|${viaTypeId ?? ''}`;
      const row = rows.get(key) ?? { key, name: relation.name, kind: relation.kind, stixStatus: relation.stixStatus, relationIds: [], counterpartIds: [], viaTypeId };
      row.relationIds.push(relation.id);
      if (!row.counterpartIds.includes(relation.sourceTypeId)) row.counterpartIds.push(relation.sourceTypeId);
      rows.set(key, row);
    }
  }
  return [...rows.values()]
    .map((row) => ({ ...row, counterpartIds: row.counterpartIds.sort((a, b) => a.localeCompare(b)) }))
    .sort((a, b) => Number(a.viaTypeId !== null) - Number(b.viaTypeId !== null) || a.name.localeCompare(b.name));
};

/** Relationship types only: every source type allowed to use it, with its targets. */
export const usageRows = (schema: NormalizedSchema, type: SchemaType): RelationRow[] => [...schema.relations.values()]
  .filter((relation) => relation.relationshipTypeId === type.id)
  .sort((a, b) => a.sourceTypeId.localeCompare(b.sourceTypeId))
  .map((relation) => ({
    key: relation.id,
    name: relation.sourceTypeId,
    kind: relation.kind,
    stixStatus: relation.stixStatus,
    relationIds: [relation.id],
    counterpartIds: relation.targetTypeIds,
    viaTypeId: null,
  }));
