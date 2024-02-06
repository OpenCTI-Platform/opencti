import { attackPatternsPaginated, dataComponentAdd, findAll, findById, withDataSource } from './dataComponent-domain';
import { stixDomainObjectAddRelation, stixDomainObjectCleanContext, stixDomainObjectDelete, stixDomainObjectDeleteRelation, stixDomainObjectEditContext, stixDomainObjectEditField } from '../../domain/stixDomainObject';
const dataComponentResolvers = {
    Query: {
        dataComponent: (_, { id }, context) => findById(context, context.user, id),
        dataComponents: (_, args, context) => findAll(context, context.user, args),
    },
    DataComponent: {
        dataSource: (dataComponent, _, context) => withDataSource(context, context.user, dataComponent.id),
        attackPatterns: (dataComponent, args, context) => attackPatternsPaginated(context, context.user, dataComponent.id, args),
    },
    Mutation: {
        dataComponentAdd: (_, { input }, context) => {
            return dataComponentAdd(context, context.user, input);
        },
        dataComponentDelete: (_, { id }, context) => {
            return stixDomainObjectDelete(context, context.user, id);
        },
        dataComponentFieldPatch: (_, { id, input, commitMessage, references }, context) => {
            return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
        },
        dataComponentContextPatch: (_, { id, input }, context) => {
            return stixDomainObjectEditContext(context, context.user, id, input);
        },
        dataComponentContextClean: (_, { id }, context) => {
            return stixDomainObjectCleanContext(context, context.user, id);
        },
        dataComponentRelationAdd: (_, { id, input }, context) => {
            return stixDomainObjectAddRelation(context, context.user, id, input);
        },
        dataComponentRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
            return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
        },
    }
};
export default dataComponentResolvers;
