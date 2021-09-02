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
  stixCoreObjectAskEnrichment,
} from '../domain/stixCoreObject';
import { creator } from '../domain/log';
import { fetchEditContext } from '../database/redis';
import { batchLoader, convertDataToRawStix } from '../database/middleware';
import { worksForSource } from '../domain/work';
import { connectorsForEnrichment } from '../domain/enrichment';

const createdByLoader = batchLoader(batchCreatedBy);
const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);
const labelsLoader = batchLoader(batchLabels);
const externalReferencesLoader = batchLoader(batchExternalReferences);
const notesLoader = batchLoader(batchNotes);
const opinionsLoader = batchLoader(batchOpinions);
const reportsLoader = batchLoader(batchReports);

const stixCoreObjectResolvers = {
  Query: {
    stixCoreObject: (_, { id }, { user }) => findById(user, id),
    stixCoreObjectRaw: (_, { id }, { user }) => convertDataToRawStix(user, id),
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
    toStix: (stixCoreObject, _, { user }) => convertDataToRawStix(user, stixCoreObject.id),
    creator: (stixCoreObject, _, { user }) => creator(user, stixCoreObject.id),
    editContext: (stixCoreObject) => fetchEditContext(stixCoreObject.id),
    stixCoreRelationships: (stixCoreObject, args, { user }) => stixCoreRelationships(user, stixCoreObject.id, args),
    createdBy: (stixCoreObject, _, { user }) => createdByLoader.load(stixCoreObject.id, user),
    objectMarking: (stixCoreObject, _, { user }) => markingDefinitionsLoader.load(stixCoreObject.id, user),
    objectLabel: (stixCoreObject, _, { user }) => labelsLoader.load(stixCoreObject.id, user),
    externalReferences: (stixCoreObject, _, { user }) => externalReferencesLoader.load(stixCoreObject.id, user),
    reports: (stixCoreObject, args, { user }) => reportsLoader.load(stixCoreObject.id, user, args),
    notes: (stixCoreObject, _, { user }) => notesLoader.load(stixCoreObject.id, user),
    opinions: (stixCoreObject, _, { user }) => opinionsLoader.load(stixCoreObject.id, user),
    jobs: (stixCyberObservable, args, { user }) => worksForSource(user, stixCyberObservable.id, args),
    connectors: (stixCyberObservable, { onlyAlive = false }, { user }) =>
      connectorsForEnrichment(user, stixCyberObservable.entity_type, onlyAlive),
  },
  Mutation: {
    stixCoreObjectEdit: (_, { id }, { user }) => ({
      relationAdd: ({ input }) => stixCoreObjectAddRelation(user, id, input),
      relationsAdd: ({ input }) => stixCoreObjectAddRelations(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixCoreObjectDeleteRelation(user, id, toId, relationshipType),
      merge: ({ stixCoreObjectsIds }) => stixCoreObjectMerge(user, id, stixCoreObjectsIds),
      askEnrichment: ({ connectorId }) => stixCoreObjectAskEnrichment(user, id, connectorId),
    }),
  },
};

export default stixCoreObjectResolvers;
