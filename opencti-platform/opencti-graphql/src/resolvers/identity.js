import { addIdentity, findAll, findById } from '../domain/identity';
import {
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete,
} from '../domain/stixDomainEntity';
import { createdBy, markingDefinitions, reports, stixRelations, labels } from '../domain/stixEntity';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../utils/idGenerator';

const identityResolvers = {
  Query: {
    identity: (_, { id }) => findById(id),
    identities: (_, args) => findAll(args),
  },
  IdentitiesOrdering: {
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
  },
  IdentitiesFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  },
  Identity: {
    // eslint-disable-next-line no-underscore-dangle
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    createdBy: (identity) => createdBy(identity.id),
    markingDefinitions: (identity) => markingDefinitions(identity.id),
    labels: (identity) => labels(identity.id),
    reports: (identity) => reports(identity.id),
    stixRelations: (identity, args) => stixRelations(identity.id, args),
  },
  Mutation: {
    identityEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(user, id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId),
    }),
    identityAdd: (_, { input }, { user }) => addIdentity(user, input),
  },
};

export default identityResolvers;
