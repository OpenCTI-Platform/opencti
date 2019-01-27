import {
  addOrganization,
  organizationDelete,
  findAll,
  findById,
  markingDefinitions,
  organizationEditContext,
  organizationEditField,
  organizationAddRelation,
  organizationDeleteRelation,
} from '../domain/organization';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const organizationResolvers = {
  Query: {
    organization: auth((_, { id }) => findById(id)),
    organizations: auth((_, args) => findAll(args))
  },
  Organization: {
    markingDefinitions: (organization, args) =>
      markingDefinitions(organization.id, args),
    editContext: auth(organization => fetchEditContext(organization.id))
  },
  Mutation: {
    organizationEdit: auth((_, { id }, { user }) => ({
      delete: () => organizationDelete(id),
      fieldPatch: ({ input }) => organizationEditField(user, id, input),
      contextPatch: ({ input }) => organizationEditContext(user, id, input),
      relationAdd: ({ input }) => organizationAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        organizationDeleteRelation(user, id, relationId)
    })),
    organizationAdd: auth((_, { input }, { user }) => addOrganization(user, input))
  }
};

export default organizationResolvers;
