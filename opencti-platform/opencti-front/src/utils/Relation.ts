import { append, includes, uniq } from 'ramda';
import { type SchemaType } from './hooks/useAuth';

// related-to is always possible
const DEFAULT_RELATION = 'related-to';

export const resolveRelationsTypes = (
  fromType: string,
  toType: string,
  schemaRelationsTypesMapping: Map<string, readonly string[]>,
  relatedTo = true,
) => {
  const typeKey = `${fromType}_${toType}`;
  const values = schemaRelationsTypesMapping.get(typeKey) ?? [];

  if (relatedTo) {
    return append(DEFAULT_RELATION, values);
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
/**
 * Starting from one entity in the "From":
 * - get list of all possible relation whatever the "To" entity is
 * - get list of allowed relation per "To" entity
 * @param from
 * @param schemaRelationsTypesMapping
 */
export interface RelationsDataFromEntity {
  allPossibleRelations: string[],
  allRelationsToEntity: RelationsToEntity[],
}
export interface RelationsToEntity {
  toEntitytype: string; // TODO rename to toDomainAndObserble or anything that says both of them.
  legitRelations: string[];
}

/**
 * Starting from one entity in the "From":
 * - get list of all possible relation whatever the "To" entity is
 * - get list of allowed relation per "To" entity
 * @param from
 * @param schema
 */
export const getRelationsFromOneEntityToAny = (
  from: string,
  schema: SchemaType,
) => {
  const { schemaRelationsTypesMapping } = schema;
  const keys = Array.from(schemaRelationsTypesMapping.keys());
  const currentEntityFromRelations = keys.filter((item) => {
    return item.startsWith(from);
  });

  const relationList = new Set<string>();
  relationList.add(DEFAULT_RELATION);
  const entityList: RelationsToEntity[] = [];

  for (let i = 0; i < currentEntityFromRelations.length; i += 1) {
    const currentRelationToEntity = schemaRelationsTypesMapping.get(currentEntityFromRelations[i]);
    const toEntityName = currentEntityFromRelations[i].substring(from.length + 1);

    const currentEntityLegitRelations = [];
    if (currentRelationToEntity) {
      for (let j = 0; j < currentRelationToEntity.length; j += 1) {
        currentEntityLegitRelations.push(currentRelationToEntity[j]);
        relationList.add(currentRelationToEntity[j]);
      }
    }

    entityList.push({
      toEntitytype: toEntityName,
      legitRelations: [...currentEntityLegitRelations, DEFAULT_RELATION],
    });
  }

  // Add all missing entities
  for (let i = 0; i < schema.sdos.length; i += 1) {
    const existingEntity = entityList.some((relationsToEntity) => relationsToEntity.toEntitytype === schema.sdos[i].id);
    if (!existingEntity) {
      entityList.push({
        toEntitytype: schema.sdos[i].id,
        legitRelations: [DEFAULT_RELATION],
      });
    }
  }

  // Add all observable + related-to
  for (let i = 0; i < schema.scos.length; i += 1) {
    entityList.push({
      toEntitytype: schema.scos[i].id,
      legitRelations: [DEFAULT_RELATION],
    });
  }

  const relationListArray = Array.from(relationList);
  return {
    allPossibleRelations: relationListArray,
    allRelationsToEntity: entityList,
  };
};
