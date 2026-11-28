import { useMemo } from 'react';
import type { NormalizedSchema } from '../../data/schemaTypes';

export interface TypeHit {
  typeId: string;
  rank: number;
}

export interface AttributeHit {
  name: string;
  /** Types declaring the attribute, each with how many types carry that declaration (itself and its subtypes). */
  declaredBy: Array<{ typeId: string; typeCount: number }>;
}

export interface SchemaSearchResult {
  types: TypeHit[];
  attributes: AttributeHit[];
}

const normalize = (value: string) => value.toLowerCase().replace(/[\s_-]+/g, '');

const rankOf = (label: string, id: string, term: string, compactTerm: string): number | null => {
  const lower = label.toLowerCase();
  if (lower === term || id.toLowerCase() === term) return 0;
  if (lower.startsWith(term)) return 1;
  if (lower.split(/[\s_-]+/).some((word) => word.startsWith(term))) return 2;
  if (lower.includes(term) || id.toLowerCase().includes(term)) return 3;
  if (compactTerm.length >= 2 && normalize(label).includes(compactTerm)) return 4;
  return null;
};

/** Ranks types by label (exact, prefix, word prefix, substring) and lists attributes whose name matches. */
export const searchSchema = (schema: NormalizedSchema, rawTerm: string, limit = 30): SchemaSearchResult => {
  const term = rawTerm.trim().toLowerCase();
  if (!term) return { types: [], attributes: [] };
  const compactTerm = normalize(term);

  const types: TypeHit[] = [];
  for (const typeId of schema.typeIds) {
    const type = schema.types.get(typeId);
    if (!type) continue;
    const rank = rankOf(type.label, type.id, term, compactTerm);
    if (rank !== null) types.push({ typeId, rank: rank + (type.category === 'Internal' ? 0.5 : 0) });
  }
  types.sort((a, b) => a.rank - b.rank || a.typeId.length - b.typeId.length || a.typeId.localeCompare(b.typeId));

  const attributes = new Map<string, { declaredBy: Map<string, number>; rank: number }>();
  if (term.length >= 2) {
    for (const type of schema.types.values()) {
      for (const attribute of type.attributes) {
        const name = attribute.name.toLowerCase();
        if (!name.includes(term)) continue;
        const hit = attributes.get(attribute.name) ?? { declaredBy: new Map<string, number>(), rank: name === term ? 0 : name.startsWith(term) ? 1 : 2 };
        hit.declaredBy.set(attribute.declaredBy, (hit.declaredBy.get(attribute.declaredBy) ?? 0) + 1);
        attributes.set(attribute.name, hit);
      }
    }
  }
  const attributeHits = [...attributes.entries()]
    .sort(([nameA, a], [nameB, b]) => a.rank - b.rank || nameA.localeCompare(nameB))
    .slice(0, 6)
    .map(([name, hit]) => ({
      name,
      declaredBy: [...hit.declaredBy.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([typeId, typeCount]) => ({ typeId, typeCount })),
    }));

  return { types: types.slice(0, limit), attributes: attributeHits };
};

export const useSchemaSearch = (schema: NormalizedSchema | null, term: string, limit?: number): SchemaSearchResult => useMemo(
  () => (schema ? searchSchema(schema, term, limit) : { types: [], attributes: [] }),
  [schema, term, limit],
);
