import { propOr } from 'ramda';
import { listRelations, loadById } from '../database/middleware';
import { ABSTRACT_STIX_RELATIONSHIP } from '../schema/general';

export const findAll = async (user, args) => listRelations(user, propOr(ABSTRACT_STIX_RELATIONSHIP, 'relationship_type', args), args);

export const findById = (user, stixRelationshipId) => {
  return loadById(user, stixRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
};
