import {
  createdBy,
  findById,
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
    toStix: (stixEntity) => convertDataToStix(stixEntity).then((stixData) => JSON.stringify(stixData)),
    creator: (stixEntity) => creator(stixEntity.id),
    createdBy: (stixEntity) => createdBy(stixEntity.id),
    objectMarking: (stixEntity) => markingDefinitions(stixEntity.id),
    objectLabel: (stixEntity) => labels(stixEntity.id),
    editContext: (stixEntity) => fetchEditContext(stixEntity.id),
    externalReferences: (stixEntity) => externalReferences(stixEntity.id),
    reports: (stixEntity) => reports(stixEntity.id),
    notes: (stixEntity) => notes(stixEntity.id),
    stixCoreRelationships: (rel, args) => stixCoreRelationships(rel.id, args),
  },
  Mutation: {
    stixCoreObjectEdit: (_, { id }, { user }) => ({
      relationAdd: ({ input }) => stixCoreObjectAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixCoreObjectDeleteRelation(user, id, relationId),
    }),
  },
};

export default stixCoreObjectResolvers;
