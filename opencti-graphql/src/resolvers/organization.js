import {
  addOrganization,
  organizationDelete,
  findAll,
  findById
} from '../domain/organization';
import {
  createdByRef,
  markingDefinitions,
  reports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const organizationResolvers = {
  Query: {
    organization: auth((_, { id }) => findById(id)),
    organizations: auth((_, args) => findAll(args))
  },
  Organization: {
    createdByRef: (organization, args) => createdByRef(organization.id, args),
    markingDefinitions: (organization, args) =>
      markingDefinitions(organization.id, args),
    reports: (organization, args) => reports(organization.id, args),
    stixRelations: (organization, args) => stixRelations(organization.id, args),
    editContext: auth(organization => fetchEditContext(organization.id))
  },
  Mutation: {
    organizationEdit: auth((_, { id }, { user }) => ({
      delete: () => organizationDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    organizationAdd: auth((_, { input }, { user }) => addOrganization(user, input))
  }
};

export default organizationResolvers;
