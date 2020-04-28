import { addIdentity, findAll, findById } from '../domain/identity';
import {
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete,
} from '../domain/stixDomainEntity';
import { createdByRef, markingDefinitions, reports, stixRelations, tags } from '../domain/stixEntity';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';

const identityResolvers = {
  Query: {
    identity: (_, { id }) => findById(id),
    identities: (_, args) => findAll(args),
  },
  IdentitiesOrdering: {
    tags: `${REL_INDEX_PREFIX}tagged.value`,
  },
  IdentitiesFilter: {
    createdBy: `${REL_INDEX_PREFIX}created_by_ref.internal_id_key`,
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.internal_id_key`,
    tags: `${REL_INDEX_PREFIX}tagged.internal_id_key`,
  },
  Identity: {
    // eslint-disable-next-line no-underscore-dangle
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    createdByRef: (identity) => createdByRef(identity.id),
    markingDefinitions: (identity) => markingDefinitions(identity.id),
    tags: (identity) => tags(identity.id),
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
