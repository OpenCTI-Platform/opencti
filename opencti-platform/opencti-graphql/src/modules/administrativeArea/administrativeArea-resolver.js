import { addAdministrativeArea, findAll, findById } from './administrativeArea-domain';
import { stixDomainObjectAddRelation, stixDomainObjectCleanContext, stixDomainObjectDelete, stixDomainObjectDeleteRelation, stixDomainObjectEditContext, stixDomainObjectEditField } from '../../domain/stixDomainObject';
import { locatedAtCountry } from '../../domain/city';
const administrativeAreaResolvers = {
    Query: {
        administrativeArea: (_, { id }, context) => findById(context, context.user, id),
        administrativeAreas: (_, args, context) => findAll(context, context.user, args),
    },
    AdministrativeArea: {
        /* eslint-disable @typescript-eslint/ban-ts-comment */
        // @ts-ignore
        country: (administrativeArea, _, context) => locatedAtCountry(context, context.user, administrativeArea.id),
    },
    Mutation: {
        administrativeAreaAdd: (_, { input }, context) => {
            return addAdministrativeArea(context, context.user, input);
        },
        administrativeAreaDelete: (_, { id }, context) => {
            return stixDomainObjectDelete(context, context.user, id);
        },
        administrativeAreaFieldPatch: (_, { id, input, commitMessage, references }, context) => {
            return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
        },
        administrativeAreaContextPatch: (_, { id, input }, context) => {
            return stixDomainObjectEditContext(context, context.user, id, input);
        },
        administrativeAreaContextClean: (_, { id }, context) => {
            return stixDomainObjectCleanContext(context, context.user, id);
        },
        administrativeAreaRelationAdd: (_, { id, input }, context) => {
            return stixDomainObjectAddRelation(context, context.user, id, input);
        },
        administrativeAreaRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
            return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
        },
    },
};
export default administrativeAreaResolvers;
