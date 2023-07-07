import { elBatchIds } from '../database/engine';
import { batchLoader } from '../database/middleware';
import { addOrganization, batchMembers, batchParentOrganizations, batchSectors, batchSubOrganizations, findAll, findById } from '../domain/organization';
import { stixDomainObjectAddRelation, stixDomainObjectCleanContext, stixDomainObjectDelete, stixDomainObjectDeleteRelation, stixDomainObjectEditContext, stixDomainObjectEditField } from '../domain/stixDomainObject';
import { buildRefRelationKey } from '../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';

const loadByIdLoader = batchLoader(elBatchIds);
const sectorsLoader = batchLoader(batchSectors);
const membersLoader = batchLoader(batchMembers);
const subOrganizationsLoader = batchLoader(batchSubOrganizations);
const parentOrganizationsLoader = batchLoader(batchParentOrganizations);

const organizationResolvers = {
  Query: {
    organization: (_, { id }, context) => findById(context, context.user, id),
    organizations: (_, args, context) => findAll(context, context.user, args),
  },
  Organization: {
    sectors: (organization, _, context) => sectorsLoader.load(organization.id, context, context.user),
    members: (organization, args, context) => membersLoader.load(organization.id, context, context.user, args),
    subOrganizations: (organization, _, context) => subOrganizationsLoader.load(organization.id, context, context.user),
    parentOrganizations: (organization, _, context) => parentOrganizationsLoader.load(organization.id, context, context.user),
    default_dashboard: (current, _, context) => loadByIdLoader.load(current.default_dashboard, context, context.user),
  },
  OrganizationsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  Mutation: {
    organizationEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    organizationAdd: (_, { input }, context) => addOrganization(context, context.user, input),
  },
};

export default organizationResolvers;
