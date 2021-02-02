import {
  findById,
  findAll,
  stixCoreObjectAddRelation,
  stixCoreObjectAddRelations,
  stixCoreObjectDeleteRelation,
  stixCoreRelationships,
  stixCoreObjectMerge,
  batchMarkingDefinitions,
  batchLabels,
  batchCreatedBy,
  batchExternalReferences,
  batchNotes,
  batchOpinions,
  batchReports,
} from '../domain/stixCoreObject';
import { creator } from '../domain/log';
import { fetchEditContext } from '../database/redis';
import { convertDataToStix } from '../database/stix';
import { ABSTRACT_STIX_CORE_OBJECT } from '../schema/general';
import { initBatchLoader, stixElementLoader } from '../database/middleware';

const createdByLoader = (user) => initBatchLoader(user, batchCreatedBy);
const markingDefinitionsLoader = (user) => initBatchLoader(user, batchMarkingDefinitions);
const labelsLoader = (user) => initBatchLoader(user, batchLabels);
const externalReferencesLoader = (user) => initBatchLoader(user, batchExternalReferences);
const notesLoader = (user) => initBatchLoader(user, batchNotes);
const opinionsLoader = (user) => initBatchLoader(user, batchOpinions);
const reportsLoader = (user) => initBatchLoader(user, batchReports);

const stixCoreObjectResolvers = {
  Query: {
    stixCoreObject: (_, { id }, { user }) => findById(user, id),
    stixCoreObjectRaw: (_, { id }, { user }) => {
      return stixElementLoader(user, id, ABSTRACT_STIX_CORE_OBJECT).then((data) => JSON.stringify(data));
    },
    stixCoreObjects: (_, args, { user }) => findAll(user, args),
  },
  StixCoreObject: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* istanbul ignore next */
      return 'Unknown';
    },
    toStix: (stixCoreObject) => JSON.stringify(convertDataToStix(stixCoreObject)),
    creator: (stixCoreObject, _, { user }) => creator(user, stixCoreObject.id),
    editContext: (stixCoreObject) => fetchEditContext(stixCoreObject.id),
    stixCoreRelationships: (stixCoreObject, args, { user }) => stixCoreRelationships(user, stixCoreObject.id, args),
    createdBy: (stixCoreObject, _, { user }) => createdByLoader(user).load(stixCoreObject.id),
    objectMarking: (stixCoreObject, _, { user }) => markingDefinitionsLoader(user).load(stixCoreObject.id),
    objectLabel: (stixCoreObject, _, { user }) => labelsLoader(user).load(stixCoreObject.id),
    externalReferences: (stixCoreObject, _, { user }) => externalReferencesLoader(user).load(stixCoreObject.id),
    reports: (stixCoreObject, _, { user }) => reportsLoader(user).load(stixCoreObject.id),
    notes: (stixCoreObject, _, { user }) => notesLoader(user).load(stixCoreObject.id),
    opinions: (stixCoreObject, _, { user }) => opinionsLoader(user).load(stixCoreObject.id),
  },
  Mutation: {
    stixCoreObjectEdit: (_, { id }, { user }) => ({
      relationAdd: ({ input }) => stixCoreObjectAddRelation(user, id, input),
      relationsAdd: ({ input }) => stixCoreObjectAddRelations(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixCoreObjectDeleteRelation(user, id, toId, relationshipType),
      merge: ({ stixCoreObjectsIds }) => stixCoreObjectMerge(user, id, stixCoreObjectsIds),
    }),
  },
};

export default stixCoreObjectResolvers;
