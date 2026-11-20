import { isRestrictedObject, type ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import type { LinkedEntity } from '@components/techniques/attack_patterns/attack_patterns_matrix/attackPatternsMatrixCellDecoration';
import type { TechniqueUsage } from './matrixTypes';

const ATTACK_PATTERN = 'Attack-Pattern';

// A relationship object carries a relationship_type; entities never do.
const isRelationship = (object: ObjectToParse) => !!object.relationship_type;

// Which end of a relationship counts for an attack pattern, if any.
// This list is the only place the scoring rules live (spec section 3).
const getScoringEnds = (relationship: ObjectToParse, from: ObjectToParse, to: ObjectToParse) => {
  const scored: { attackPattern: ObjectToParse; entity: ObjectToParse }[] = [];
  switch (relationship.relationship_type) {
    case 'uses':
      if (from.entity_type === ATTACK_PATTERN) scored.push({ attackPattern: from, entity: to });
      if (to.entity_type === ATTACK_PATTERN) scored.push({ attackPattern: to, entity: from });
      break;
    case 'indicates':
    case 'object':
      if (to.entity_type === ATTACK_PATTERN) scored.push({ attackPattern: to, entity: from });
      break;
    default:
      break;
  }
  return scored;
};

export interface ScoringLink { relationship: ObjectToParse; attackPattern: ObjectToParse; entity: ObjectToParse }

/** Every relationship that scores an attack pattern, with its two ends; restricted ends left out. */
export const getScoringLinks = (rawObjects: ObjectToParse[]): ScoringLink[] => {
  const index = new Map<string, ObjectToParse>();
  rawObjects.forEach((object) => index.set(object.id, object));

  return rawObjects.flatMap((relationship) => {
    if (!isRelationship(relationship)) return [];
    const fromId = relationship.from?.id;
    const toId = relationship.to?.id;
    if (!fromId || !toId) return [];
    const from = index.get(fromId);
    const to = index.get(toId);
    // Both ends must be in the investigation, and neither may be a relationship.
    if (!from || !to || isRelationship(from) || isRelationship(to)) return [];
    return getScoringEnds(relationship, from, to)
      // An entity the user cannot read neither scores nor appears in a hover list: its link to a technique stays hidden.
      .filter(({ attackPattern, entity }) => !isRestrictedObject(attackPattern) && !isRestrictedObject(entity))
      .map(({ attackPattern, entity }) => ({ relationship, attackPattern, entity }));
  });
};

export const analyseTechniqueUsage = (rawObjects: ObjectToParse[]): Map<string, TechniqueUsage> => {
  const entitiesByTechnique = new Map<string, Map<string, LinkedEntity>>();
  getScoringLinks(rawObjects).forEach(({ attackPattern, entity }) => {
    let entities = entitiesByTechnique.get(attackPattern.id);
    if (!entities) {
      entities = new Map();
      entitiesByTechnique.set(attackPattern.id, entities);
    }
    if (!entities.has(entity.id)) {
      entities.set(entity.id, { id: entity.id, name: getMainRepresentative(entity), entity_type: entity.entity_type });
    }
  });

  const usage = new Map<string, TechniqueUsage>();
  entitiesByTechnique.forEach((entities, attackPatternId) => {
    usage.set(attackPatternId, {
      attackPatternId,
      score: entities.size,
      linkedEntities: Array.from(entities.values()),
    });
  });
  return usage;
};
