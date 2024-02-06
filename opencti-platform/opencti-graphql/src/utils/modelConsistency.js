var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { checkRelationshipRef, checkStixCoreRelationshipMapping } from '../database/stix';
import { FunctionalError } from '../config/errors';
import { telemetry } from '../config/tracing';
import { isStixRefRelationship } from '../schema/stixRefRelationship';
export const checkRelationConsistency = (context, user, relationshipType, from, to) => __awaiter(void 0, void 0, void 0, function* () {
    const checkRelationConsistencyFn = () => __awaiter(void 0, void 0, void 0, function* () {
        // 01 - check type consistency
        const fromType = from.entity_type;
        const arrayTo = Array.isArray(to) ? to : [to];
        arrayTo.forEach(({ entity_type: toType }) => {
            // Check if StixCoreRelationship is allowed
            if (isStixCoreRelationship(relationshipType)) {
                if (!checkStixCoreRelationshipMapping(fromType, toType, relationshipType)) {
                    throw FunctionalError(`The relationship type ${relationshipType} is not allowed between ${fromType} and ${toType}`);
                }
            }
            else if (isStixRefRelationship(relationshipType)) {
                checkRelationshipRef(fromType, toType, relationshipType);
            }
        });
    });
    return telemetry(context, user, 'CONSISTENCY relation', {
        [SemanticAttributes.DB_NAME]: 'search_engine',
        [SemanticAttributes.DB_OPERATION]: 'read',
    }, checkRelationConsistencyFn);
});
export const isRelationConsistent = (context, user, relationshipType, from, to) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        yield checkRelationConsistency(context, user, relationshipType, from, to);
        return true;
    }
    catch (_a) {
        return false;
    }
});
