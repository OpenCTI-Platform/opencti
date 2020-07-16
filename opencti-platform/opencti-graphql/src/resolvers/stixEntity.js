import {
  createdBy,
  findById,
  markingDefinitions,
  reports,
  notes,
  labels,
  externalReferences,
  stixEntityAddRelation,
  stixEntityDeleteRelation,
} from '../domain/stixEntity';
import { creator } from '../domain/log';
import { fetchEditContext } from '../database/redis';
import { convertDataToStix } from '../database/stix';

const stixEntityResolvers = {
  Query: {
    stixEntity: (_, { id }) => findById(id),
  },
  StixEntity: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.observable_value) {
        return 'StixObservable';
      }
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* istanbul ignore next */
      return 'Unknown';
    },
    toStix: (stixEntity) => convertDataToStix(stixEntity).then((stixData) => JSON.stringify(stixData)),
    creator: (stixEntity) => creator(stixEntity.id),
    createdBy: (stixEntity) => createdBy(stixEntity.id),
    editContext: (stixEntity) => fetchEditContext(stixEntity.id),
    externalReferences: (stixEntity) => externalReferences(stixEntity.id),
    labels: (stixEntity) => labels(stixEntity.id),
    reports: (stixEntity) => reports(stixEntity.id),
    notes: (stixEntity) => notes(stixEntity.id),
    markingDefinitions: (stixEntity) => markingDefinitions(stixEntity.id),
  },
  Mutation: {
    stixEntityEdit: (_, { id }, { user }) => ({
      relationAdd: ({ input }) => stixEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixEntityDeleteRelation(user, id, relationId),
    }),
  },
};

export default stixEntityResolvers;
