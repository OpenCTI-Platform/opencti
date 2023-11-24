import { addLocation, findAll, findById } from '../domain/location';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../modules/administrativeArea/administrativeArea-types';

const locationResolvers = {
  Query: {
    location: (_, { id }, context) => findById(context, context.user, id),
    locations: (_, args, context) => findAll(context, context.user, args),
  },
  Location: {
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
  },
  LocationType: {
    AdministrativeArea: ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA,
  },
  Mutation: {
    locationEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    locationAdd: (_, { input }, context) => addLocation(context, context.user, input),
  },
};

export default locationResolvers;
