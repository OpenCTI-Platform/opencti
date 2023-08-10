import * as R from 'ramda';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { ABSTRACT_STIX_META_OBJECT } from '../schema/general';
import { isNotEmptyField } from '../database/utils';
import { isStixMetaObject } from '../schema/stixMetaObject';

export const findById = async (context, user, stixMetaObjectId) => {
  return storeLoadById(context, user, stixMetaObjectId, ABSTRACT_STIX_META_OBJECT);
};

export const findAll = async (context, user, args) => {
  let types = [];
  if (isNotEmptyField(args.types)) {
    types = R.filter((type) => isStixMetaObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_META_OBJECT);
  }
  return listEntities(context, user, types, args);
};
