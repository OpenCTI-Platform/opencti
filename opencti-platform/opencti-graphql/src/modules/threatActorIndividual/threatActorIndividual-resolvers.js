import { addThreatActorIndividual, findAll, findById, } from './threatActorIndividual-domain';
import { stixDomainObjectAddRelation, stixDomainObjectCleanContext, stixDomainObjectDelete, stixDomainObjectDeleteRelation, stixDomainObjectEditContext, stixDomainObjectEditField } from '../../domain/stixDomainObject';
import { utcDate } from '../../utils/format';
import { loadThroughDenormalized } from '../../resolvers/stix';
import { INPUT_BORN_IN, INPUT_ETHNICITY } from '../../schema/general';
const threatActorIndividualResolvers = {
    Query: {
        threatActorIndividual: (_, { id }, context) => findById(context, context.user, id),
        threatActorsIndividuals: (_, args, context) => findAll(context, context.user, args),
    },
    ThreatActorIndividual: {
        bornIn: (threatActorIndividual, _, context) => loadThroughDenormalized(context, context.user, threatActorIndividual, INPUT_BORN_IN),
        ethnicity: (threatActorIndividual, _, context) => loadThroughDenormalized(context, context.user, threatActorIndividual, INPUT_ETHNICITY),
        height: (threatActorIndividual, _, __) => {
            var _a;
            return ((_a = threatActorIndividual.height) !== null && _a !== void 0 ? _a : [])
                .map((height, index) => (Object.assign(Object.assign({}, height), { index })))
                .sort((a, b) => utcDate(a.date_seen).diff(utcDate(b.date_seen)));
        },
        weight: (threatActorIndividual, _, __) => {
            var _a;
            return ((_a = threatActorIndividual.weight) !== null && _a !== void 0 ? _a : [])
                .map((weight, index) => (Object.assign(Object.assign({}, weight), { index })))
                .sort((a, b) => utcDate(a.date_seen).diff(utcDate(b.date_seen)));
        },
    },
    Mutation: {
        threatActorIndividualAdd: (_, { input }, context) => {
            return addThreatActorIndividual(context, context.user, input);
        },
        threatActorIndividualDelete: (_, { id }, context) => {
            return stixDomainObjectDelete(context, context.user, id);
        },
        threatActorIndividualFieldPatch: (_, { id, input }, context) => {
            return stixDomainObjectEditField(context, context.user, id, input);
        },
        threatActorIndividualContextPatch: (_, { id, input }, context) => {
            return stixDomainObjectEditContext(context, context.user, id, input);
        },
        threatActorIndividualContextClean: (_, { id }, context) => {
            return stixDomainObjectCleanContext(context, context.user, id);
        },
        threatActorIndividualRelationAdd: (_, { id, input }, context) => {
            return stixDomainObjectAddRelation(context, context.user, id, input);
        },
        threatActorIndividualRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
            return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
        },
    },
};
export default threatActorIndividualResolvers;
