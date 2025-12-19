import { findStixMetaObjectPaginated, findById } from '../domain/stixMetaObject';
import { getSpecVersionOrDefault } from '../domain/stixRelationship';

const stixMetaObjectResolvers = {
  Query: {
    stixMetaObject: (_, { id }, context) => findById(context, context.user, id),
    stixMetaObjects: (_, args, context) => findStixMetaObjectPaginated(context, context.user, args),
  },
  StixMetaObject: {

    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* v8 ignore next */
      return 'Unknown';
    },
    // Retro compatibility
    spec_version: getSpecVersionOrDefault,
  },
};

export default stixMetaObjectResolvers;
