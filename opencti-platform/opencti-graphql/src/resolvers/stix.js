import { stixDelete, stixObjectMerge } from '../domain/stix';
import { batchLoader, stixLoadByIdStringify } from '../database/middleware';
import { connectorsForEnrichment } from '../database/repository';
import { batchCreators } from '../domain/user';
import { batchInternalRels } from '../domain/stixCoreObject';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';

const creatorsLoader = batchLoader(batchCreators);
const relBatchLoader = batchLoader(batchInternalRels);
export const loadThroughDenormalized = (context, user, element, inputName) => {
  if (element[inputName]) {
    // if element is already loaded, just send the data
    return element[inputName];
  }
  // If not, reload through denormalized relationships
  const ref = schemaRelationsRefDefinition.getRelationRef(element.entity_type, inputName);
  return relBatchLoader.load({ element, type: ref.databaseName }, context, user);
};

const stixResolvers = {
  Query: {
    stix: async (_, { id }, context) => stixLoadByIdStringify(context, context.user, id),
    enrichmentConnectors: (_, { type }, context) => connectorsForEnrichment(context, context.user, type, true),
  },
  Mutation: {
    stixEdit: (_, { id }, context) => ({
      delete: () => stixDelete(context, context.user, id),
      merge: ({ stixObjectsIds }) => stixObjectMerge(context, context.user, id, stixObjectsIds),
    }),
  },
  StixObject: {
    // eslint-disable-next-line
        __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* v8 ignore next */
      return 'Unknown';
    },
    creators: (stix, _, context) => creatorsLoader.load(stix.creator_id, context, context.user),
  },
};

export default stixResolvers;
