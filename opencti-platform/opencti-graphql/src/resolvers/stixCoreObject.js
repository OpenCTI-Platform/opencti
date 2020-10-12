import {
  createdBy,
  findById,
  findAll,
  markingDefinitions,
  reports,
  notes,
  labels,
  externalReferences,
  stixCoreObjectAddRelation,
  stixCoreObjectAddRelations,
  stixCoreObjectDeleteRelation,
  stixCoreRelationships,
  stixCoreObjectMerge,
} from '../domain/stixCoreObject';
import { creator } from '../domain/log';
import { fetchEditContext } from '../database/redis';
import { convertDataToStix } from '../database/stix';
import { ABSTRACT_STIX_CORE_OBJECT } from '../schema/general';
import { initBatchLoader, stixElementLoader } from '../database/grakn';

const createdByLoader = initBatchLoader(createdBy);
const markingLoader = initBatchLoader(markingDefinitions);
const labelLoader = initBatchLoader(labels);

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
    externalReferences: (stixCoreObject) => externalReferences(stixCoreObject.id),
    reports: (stixCoreObject) => reports(stixCoreObject.id),
    notes: (stixCoreObject) => notes(stixCoreObject.id),
    stixCoreRelationships: (stixCoreObject, args) => stixCoreRelationships(stixCoreObject.id, args),
    // Bulk loaders
    createdBy: (stixCoreObject) => createdByLoader.load(stixCoreObject.id),
    objectMarking: (stixCoreObject) => markingLoader.load(stixCoreObject.id),
    objectLabel: (stixCoreObject) => labelLoader.load(stixCoreObject.id),
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
