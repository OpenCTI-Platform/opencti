import { append, includes, uniq } from 'ramda';

export const resolveRelationsTypes = (
  fromType: string,
  toType: string,
  schemaRelationsTypesMapping: Map<string, readonly string[]>,
  relatedTo = true,
) => {
  const typeKey = `${fromType}_${toType}`;
  const values = schemaRelationsTypesMapping.get(typeKey) ?? [];

  if (relatedTo) {
    return append('related-to', values);
  }
  return values;
};

export const hasKillChainPhase = (type: string) => includes(type, ['uses', 'exploits', 'drops', 'indicates']);

// retro-compatibility with cyber-observable-relationship
export const isStixNestedRefRelationship = (type: string) => ['stix-ref-relationship', 'stix-cyber-observable-relationship'].includes(type);

export const resolveTypesForRelationship = (
  schemaRelationsTypesMapping: Map<string, readonly string[]>,
  relationshipType: string,
  relationshipRefKey: string,
  fromType?: string,
  toType?: string,
) => {
  const types: string[] = [];

  schemaRelationsTypesMapping.forEach((values, key) => {
    if (values.includes(relationshipType)) {
      const [from, to] = key.split('_');
      if (relationshipRefKey === 'from') {
        if (!toType || toType === to) {
          types.push(from);
        }
      } else if (relationshipRefKey === 'to') {
        if (!fromType || fromType === from) {
          types.push(to);
        }
      }
    }
  });
  return uniq(types);
};

export const resolveTypesForRelationshipRef = (
  schemaRelationsTypesMapping: Map<string, readonly { readonly name: string, readonly toTypes: readonly string[] }[]>,
  entityType: string,
  relationshipRefKey: string,
) => {
  return schemaRelationsTypesMapping
    .get(entityType)
    ?.find((ref) => ref.name === relationshipRefKey)
    ?.toTypes ?? [];
};
