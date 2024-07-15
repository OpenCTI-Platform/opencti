import { sendStixBundle, stixDelete, stixObjectMerge } from '../domain/stix';
import { batchLoader, stixLoadByIdStringify } from '../database/middleware';
import { connectorsForEnrichment } from '../database/repository';
import { batchCreators } from '../domain/user';
import { batchInternalRels } from '../domain/stixCoreObject';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { INPUT_GRANTED_REFS } from '../schema/general';
import { isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT } from '../utils/access';
import { buildPagination } from '../database/utils';

const creatorsLoader = batchLoader(batchCreators);
const relBatchLoader = batchLoader(batchInternalRels);
export const loadThroughDenormalized = (context, user, element, inputName, args = {}) => {
  if (inputName === INPUT_GRANTED_REFS) {
    if (!isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT)) {
      return []; // Granted_refs visibility is only for manager
    }
    const ref = schemaRelationsRefDefinition.getRelationRef(element.entity_type, inputName);
    if (!ref) {
      return []; // Granted_refs are not part of all core entities
    }
  }
  if (element[inputName]) {
    // if element is already loaded, just send the data
    return element[inputName];
  }
  // If not, reload through denormalized relationships
  const ref = schemaRelationsRefDefinition.getRelationRef(element.entity_type, inputName);
  return relBatchLoader.load({ element, definition: ref }, context, user, args);
};

// Load everything but return a connection format - for retro compatibility
export const loadThroughDenormalizedConnections = async (context, user, element, inputName, args = {}) => {
  const externalRefs = await loadThroughDenormalized(context, user, element, inputName, args);
  const nodeElements = externalRefs.map((externalRef) => ({ node: externalRef }));
  return buildPagination(0, null, nodeElements, nodeElements.length);
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
    stixBundlePush: (_, { connectorId, bundle }, context) => sendStixBundle(context, context.user, connectorId, bundle),
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
