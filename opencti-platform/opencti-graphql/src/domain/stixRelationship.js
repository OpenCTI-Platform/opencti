import { propOr } from 'ramda';
import { deleteElementById } from '../database/middleware';
import { ABSTRACT_STIX_RELATIONSHIP } from '../schema/general';
import { listRelations, storeLoadById } from '../database/middleware-loader';
import { STIX_SPEC_VERSION } from '../database/stix';

export const findAll = async (context, user, args) => {
  return listRelations(context, user, propOr(ABSTRACT_STIX_RELATIONSHIP, 'relationship_type', args), args);
};

export const findById = (context, user, stixRelationshipId) => {
  return storeLoadById(context, user, stixRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
};

export const stixRelationshipDelete = async (context, user, stixRelationshipId) => {
  await deleteElementById(context, user, stixRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
  return stixRelationshipId;
};

export const getSpecVersionOrDefault = ({ spec_version }) => spec_version ?? STIX_SPEC_VERSION;
