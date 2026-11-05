import type { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import type { LinkedEntity, TechniqueUsage } from './matrixTypes';

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

export const analyseTechniqueUsage = (rawObjects: ObjectToParse[]): Map<string, TechniqueUsage> => {
  const index = new Map<string, ObjectToParse>();
  rawObjects.forEach((object) => index.set(object.id, object));

  const entitiesByTechnique = new Map<string, Map<string, LinkedEntity>>();
  rawObjects.forEach((relationship) => {
    if (!isRelationship(relationship)) return;
    const fromId = relationship.from?.id;
    const toId = relationship.to?.id;
    if (!fromId || !toId) return;
    const from = index.get(fromId);
    const to = index.get(toId);
    // Both ends must be in the investigation, and neither may be a relationship.
    if (!from || !to || isRelationship(from) || isRelationship(to)) return;
    getScoringEnds(relationship, from, to).forEach(({ attackPattern, entity }) => {
      let entities = entitiesByTechnique.get(attackPattern.id);
      if (!entities) {
        entities = new Map();
        entitiesByTechnique.set(attackPattern.id, entities);
      }
      if (!entities.has(entity.id)) {
        entities.set(entity.id, { id: entity.id, name: getMainRepresentative(entity), entity_type: entity.entity_type });
      }
    });
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
