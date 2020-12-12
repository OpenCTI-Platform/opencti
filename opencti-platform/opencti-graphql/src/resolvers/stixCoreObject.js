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

const createdByLoader = initBatchLoader(batchCreatedBy);
const markingDefinitionsLoader = initBatchLoader(batchMarkingDefinitions);
const labelsLoader = initBatchLoader(batchLabels);
const externalReferencesLoader = initBatchLoader(batchExternalReferences);
const notesLoader = initBatchLoader(batchNotes);
const opinionsLoader = initBatchLoader(batchOpinions);
const reportsLoader = initBatchLoader(batchReports);

const stixCoreObjectResolvers = {
  Query: {
    stixCoreObject: (_, { id }) => findById(id),
    stixCoreObjectRaw: (_, { id }) => {
      return stixElementLoader(id, ABSTRACT_STIX_CORE_OBJECT).then((data) => JSON.stringify(data));
    },
    stixCoreObjects: (_, args) => findAll(args),
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
    creator: (stixCoreObject) => creator(stixCoreObject.id),
    editContext: (stixCoreObject) => fetchEditContext(stixCoreObject.id),
    stixCoreRelationships: (stixCoreObject, args) => stixCoreRelationships(stixCoreObject.id, args),
    createdBy: (stixCoreObject) => createdByLoader.load(stixCoreObject.id),
    objectMarking: (stixCoreObject) => markingDefinitionsLoader.load(stixCoreObject.id),
    objectLabel: (stixCoreObject) => labelsLoader.load(stixCoreObject.id),
    externalReferences: (stixCoreObject) => externalReferencesLoader.load(stixCoreObject.id),
    reports: (stixCoreObject) => reportsLoader.load(stixCoreObject.id),
    notes: (stixCoreObject) => notesLoader.load(stixCoreObject.id),
    opinions: (stixCoreObject) => opinionsLoader.load(stixCoreObject.id),
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
