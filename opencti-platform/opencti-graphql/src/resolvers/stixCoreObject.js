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
  stixCoreObjectDeleteRelation,
  stixCoreRelationships,
} from '../domain/stixCoreObject';
import { creator } from '../domain/log';
import { fetchEditContext } from '../database/redis';
import { convertDataToStix } from '../database/stix';

const stixCoreObjectResolvers = {
  Query: {
    stixCoreObject: (_, { id }) => findById(id),
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
    toStix: (stixCoreObject) => convertDataToStix(stixCoreObject).then((stixData) => JSON.stringify(stixData)),
    creator: (stixCoreObject) => creator(stixCoreObject.id),
    createdBy: (stixCoreObject) => createdBy(stixCoreObject.id),
    objectMarking: (stixCoreObject) => markingDefinitions(stixCoreObject.id),
    objectLabel: (stixCoreObject) => labels(stixCoreObject.id),
    editContext: (stixCoreObject) => fetchEditContext(stixCoreObject.id),
    externalReferences: (stixCoreObject) => externalReferences(stixCoreObject.id),
    reports: (stixCoreObject) => reports(stixCoreObject.id),
    notes: (stixCoreObject) => notes(stixCoreObject.id),
    stixCoreRelationships: (rel, args) => stixCoreRelationships(rel.id, args),
  },
  Mutation: {
    stixCoreObjectEdit: (_, { id }, { user }) => ({
      relationAdd: ({ input }) => stixCoreObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixCoreObjectDeleteRelation(user, id, toId, relationshipType),
    }),
  },
};

export default stixCoreObjectResolvers;
