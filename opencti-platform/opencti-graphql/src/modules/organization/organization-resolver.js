import { elBatchIds } from '../../database/engine';
import { batchLoader } from '../../database/middleware';
import { addOrganization, buildAdministratedOrganizations, childOrganizationsPaginated, editAuthorizedAuthorities, findAll, findById, findGrantableGroups, organizationAdminAdd, organizationAdminRemove, organizationMembersPaginated, organizationSectorsPaginated, parentOrganizationsPaginated } from './organization-domain';
import { stixDomainObjectAddRelation, stixDomainObjectCleanContext, stixDomainObjectDelete, stixDomainObjectDeleteRelation, stixDomainObjectEditContext, stixDomainObjectEditField } from '../../domain/stixDomainObject';
import { ENTITY_TYPE_WORKSPACE } from '../workspace/workspace-types';
const loadByIdLoader = batchLoader(elBatchIds);
const organizationResolvers = {
    Query: {
        organization: (_, { id }, context) => findById(context, context.user, id),
        organizations: (_, args, context) => findAll(context, context.user, args),
    },
    Organization: {
        sectors: (organization, args, context) => organizationSectorsPaginated(context, context.user, organization.id, args),
        members: (organization, args, context) => organizationMembersPaginated(context, context.user, organization.id, args),
        subOrganizations: (organization, args, context) => childOrganizationsPaginated(context, context.user, organization.id, args),
        parentOrganizations: (organization, args, context) => parentOrganizationsPaginated(context, context.user, organization.id, args),
        default_dashboard: (current, _, context) => loadByIdLoader.load({ id: current.default_dashboard, type: ENTITY_TYPE_WORKSPACE }, context, context.user),
        grantable_groups: (organization, _, context) => findGrantableGroups(context, context.user, organization),
    },
    User: {
        administrated_organizations: (user, _, context) => buildAdministratedOrganizations(context, context.user, user),
    },
    Mutation: {
        organizationAdd: (_, { input }, context) => addOrganization(context, context.user, input),
        organizationDelete: (_, { id }, context) => stixDomainObjectDelete(context, context.user, id),
        organizationFieldPatch: (_, { id, input, commitMessage, references }, context) => {
            return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
        },
        organizationContextPatch: (_, { id, input }, context) => stixDomainObjectEditContext(context, context.user, id, input),
        organizationContextClean: (_, { id }, context) => stixDomainObjectCleanContext(context, context.user, id),
        organizationRelationAdd: (_, { id, input }, context) => stixDomainObjectAddRelation(context, context.user, id, input),
        organizationRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
            return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
        },
        organizationEditAuthorizedAuthorities: (_, { id, input }, context) => {
            return editAuthorizedAuthorities(context, context.user, id, input);
        },
        organizationAdminAdd: (_, { id, memberId }, context) => {
            return organizationAdminAdd(context, context.user, id, memberId);
        },
        organizationAdminRemove: (_, { id, memberId }, context) => {
            return organizationAdminRemove(context, context.user, id, memberId);
        },
    },
};
export default organizationResolvers;
