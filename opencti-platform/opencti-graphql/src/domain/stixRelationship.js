import { propOr } from 'ramda';
import { deleteElementById, storeLoadById } from '../database/middleware';
import { ABSTRACT_STIX_RELATIONSHIP } from '../schema/general';
import { listRelations } from '../database/middleware-loader';

export const findAll = async (user, args) => {
  return listRelations(user, propOr(ABSTRACT_STIX_RELATIONSHIP, 'relationship_type', args), args);
};

export const findById = (user, stixRelationshipId) => {
  return storeLoadById(user, stixRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
};

export const stixRelationshipDelete = async (user, stixRelationshipId) => {
  return deleteElementById(user, stixRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
};
