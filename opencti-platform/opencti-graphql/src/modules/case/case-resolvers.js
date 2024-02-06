var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Promise as BluePromise } from 'bluebird';
import { stixDomainObjectDelete } from '../../domain/stixDomainObject';
import { findAll, findById, upsertTemplateForCase } from './case-domain';
import { caseTasksPaginated } from '../task/task-domain';
import { loadThroughDenormalized } from '../../resolvers/stix';
import { INPUT_PARTICIPANT } from '../../schema/general';
const caseResolvers = {
    Query: {
        case: (_, { id }, context) => findById(context, context.user, id),
        cases: (_, args, context) => findAll(context, context.user, args),
    },
    Case: {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        __resolveType(obj) {
            if (obj.entity_type) {
                return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
            }
            return 'Unknown';
        },
        tasks: (current, args, context) => caseTasksPaginated(context, context.user, current.id, args),
        objectParticipant: (container, _, context) => loadThroughDenormalized(context, context.user, container, INPUT_PARTICIPANT, { sortBy: 'user_email' }),
    },
    CasesOrdering: {
        creator: 'creator_id',
    },
    Mutation: {
        caseDelete: (_, { id }, context) => {
            return stixDomainObjectDelete(context, context.user, id);
        },
        caseSetTemplate: (_, { id, caseTemplatesId }, context) => __awaiter(void 0, void 0, void 0, function* () {
            yield BluePromise.map(caseTemplatesId, (caseTemplateId) => upsertTemplateForCase(context, context.user, id, caseTemplateId));
            return findById(context, context.user, id);
        }),
    }
};
export default caseResolvers;
