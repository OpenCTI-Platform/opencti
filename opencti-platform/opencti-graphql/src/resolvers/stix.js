import { sendStixBundle, stixDelete, stixObjectMerge } from '../domain/stix';
import { batchLoader, stixLoadByIdStringify } from '../database/middleware';
import { connectorsForEnrichment } from '../database/repository';
import { batchCreators } from '../domain/user';
import { batchInternalRels } from '../domain/stixCoreObject';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { INPUT_GRANTED_REFS } from '../schema/general';
import { isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT, REDACTED_USER } from '../utils/access';
import { ENABLED_DEMO_MODE } from '../config/conf';
import { ENTITY_TYPE_USER } from '../schema/internalObject';

const creatorsLoader = batchLoader(batchCreators);
const relBatchLoader = batchLoader(batchInternalRels);
const internalLoadThroughDenormalized = (context, user, element, inputName, args = {}) => {
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

export const loadThroughDenormalized = async (context, user, element, inputName, args = {}) => {
  const data = await internalLoadThroughDenormalized(context, user, element, inputName, args);
  if (ENABLED_DEMO_MODE) {
    if (Array.isArray(data)) {
      return data.map((d) => {
        if (d.entity_type === ENTITY_TYPE_USER) {
          return { ...d, name: REDACTED_USER.name, user_email: REDACTED_USER.user_email };
        }
        return d;
      });
    }
    return data ? { ...data, name: REDACTED_USER.name, user_email: REDACTED_USER.user_email } : data;
  }
  return data;
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
    stixBundlePush: (_, { connectorId, bundle, work_id }, context) => sendStixBundle(context, context.user, connectorId, bundle, work_id),
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
