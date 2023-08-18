import { append, includes } from 'ramda';

export const resolveRelationsTypes = (
  fromType: string,
  toType: string,
  schemaRelationsTypesMapping: readonly { readonly key: string, readonly values: readonly string[] }[],
  relatedTo = true,
) => {
  const typeKey = `${fromType}_${toType}`;
  const values = schemaRelationsTypesMapping.filter((def) => typeKey === def.key)
    .map((def) => def.values).flat();

  if (relatedTo) {
    return append('related-to', values);
  }
  return values;
};

export const hasKillChainPhase = (type: string) => includes(type, ['uses', 'exploits', 'drops', 'indicates']);

export const onlyLinkedTo = (relationshipTypes: string[]) => relationshipTypes.length === 1 && relationshipTypes.includes('x_opencti_linked-to');

// retro-compatibility with cyber-observable-relationship
export const isStixNestedRefRelationship = (type: string) => ['stix-ref-relationship', 'stix-cyber-observable-relationship'].includes(type);
