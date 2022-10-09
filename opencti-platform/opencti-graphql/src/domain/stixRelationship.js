import { propOr } from 'ramda';
import { deleteElementById, storeLoadById } from '../database/middleware';
import { ABSTRACT_STIX_RELATIONSHIP } from '../schema/general';
import { listRelations } from '../database/middleware-loader';

export const findAll = async (context, user, args) => {
  return listRelations(context, user, propOr(ABSTRACT_STIX_RELATIONSHIP, 'relationship_type', args), args);
};

export const findById = (context, user, stixRelationshipId) => {
  return storeLoadById(context, user, stixRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
};

export const stixRelationshipDelete = async (context, user, stixRelationshipId) => {
  return deleteElementById(context, user, stixRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
};
