import { assoc, dissoc, propOr } from 'ramda';
import { elCount } from '../database/engine';
import { ABSTRACT_STIX_META_RELATIONSHIP } from '../schema/general';
import { isStixMetaRelationship } from '../schema/stixMetaRelationship';
import { READ_INDEX_STIX_META_RELATIONSHIPS } from '../database/utils';
import { listRelations, storeLoadById } from '../database/middleware-loader';

export const findAll = async (context, user, args) => {
  return listRelations(context, user, propOr(ABSTRACT_STIX_META_RELATIONSHIP, 'relationship_type', args), args);
};

export const findById = (context, user, stixRelationshipId) => {
  return storeLoadById(context, user, stixRelationshipId, ABSTRACT_STIX_META_RELATIONSHIP);
};

export const stixMetaRelationshipsNumber = (context, user, args) => {
  const types = [];
  if (args.type) {
    if (isStixMetaRelationship(args.type)) {
      types.push(args.type);
    }
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_META_RELATIONSHIP);
  }
  const finalArgs = assoc('types', types, args);
  return {
    count: elCount(context, user, READ_INDEX_STIX_META_RELATIONSHIPS, finalArgs),
    total: elCount(context, user, READ_INDEX_STIX_META_RELATIONSHIPS, dissoc('endDate', finalArgs)),
  };
};
