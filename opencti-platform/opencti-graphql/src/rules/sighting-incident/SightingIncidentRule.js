var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/* eslint-disable camelcase */
import { createInferredEntity, createInferredRelation, deleteInferredRuleElement, stixLoadById } from '../../database/middleware';
import def from './SightingIncidentDefinition';
import { ENTITY_TYPE_INCIDENT } from '../../schema/stixDomainObject';
import { createRuleContent } from '../rules-utils';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';
import { RELATION_RELATED_TO, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import { listAllRelations } from '../../database/middleware-loader';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { executionContext, RULE_MANAGER_USER } from '../../utils/access';
import { ENTITY_TYPE_INDICATOR } from '../../modules/indicator/indicator-types';
// 'If **indicator A** has `revoked` **false** and **indicator A** is `sighted` in ' +
// '**identity B**, then create **Incident C** `related-to` **indicator A** and ' +
// '`targets` **identity B**.';
const ruleSightingIncidentBuilder = () => {
    const { id } = def;
    // Execution
    const generateDependencies = (indicatorId, stixSightingId, identityId) => {
        return [
            // Entities dependencies
            indicatorId,
            `${indicatorId}_revoked:${false}`,
            identityId,
            // Relations dependencies
            stixSightingId,
        ];
    };
    const handleIndicatorUpsert = (context, indicator) => __awaiter(void 0, void 0, void 0, function* () {
        const { extensions } = indicator;
        const indicatorId = extensions[STIX_EXT_OCTI].id;
        const { name, pattern, revoked, object_marking_refs, confidence } = indicator;
        if (!revoked) {
            const sightingsArgs = { toType: ENTITY_TYPE_IDENTITY, fromId: indicatorId };
            const sightingsRelations = yield listAllRelations(context, RULE_MANAGER_USER, STIX_SIGHTING_RELATIONSHIP, sightingsArgs);
            for (let index = 0; index < sightingsRelations.length; index += 1) {
                const { internal_id: sightingId, toId: identityId, first_seen, last_seen } = sightingsRelations[index];
                const dependencies = generateDependencies(indicatorId, identityId, sightingId);
                // Create the incident with everything
                const explanation = [indicatorId, identityId, sightingId];
                const input = {
                    name: `Sighting on valid indicator ${name}`,
                    description: `Automatically generated incident based on indicator pattern: ${pattern}`,
                };
                const ruleBaseContent = { confidence, objectMarking: object_marking_refs };
                const ruleContentData = Object.assign(Object.assign({}, ruleBaseContent), { first_seen, last_seen });
                const ruleContent = createRuleContent(id, dependencies, explanation, ruleContentData);
                const inferredEntity = yield createInferredEntity(context, input, ruleContent, ENTITY_TYPE_INCIDENT);
                const ruleRelContent = createRuleContent(id, dependencies, explanation, ruleBaseContent);
                // Create **Incident C** `related-to` **indicator A**
                const created = inferredEntity.element;
                const incidentToIndicator = { fromId: created.internal_id, toId: indicatorId, relationship_type: RELATION_RELATED_TO };
                yield createInferredRelation(context, incidentToIndicator, ruleRelContent);
                // Create **Incident C** `targets` **identity B**
                const incidentToIdentity = { fromId: created.internal_id, toId: identityId, relationship_type: RELATION_TARGETS };
                yield createInferredRelation(context, incidentToIdentity, ruleRelContent);
            }
        }
    });
    const handleIndicatorRelationUpsert = (context, sightingRelation) => __awaiter(void 0, void 0, void 0, function* () {
        const indicatorId = sightingRelation.extensions[STIX_EXT_OCTI].sighting_of_ref;
        const sightingIndicator = yield stixLoadById(context, RULE_MANAGER_USER, indicatorId);
        return handleIndicatorUpsert(context, sightingIndicator);
    });
    const applyUpsert = (data) => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext(def.name, RULE_MANAGER_USER);
        const entityType = generateInternalType(data);
        if (entityType === ENTITY_TYPE_INDICATOR) {
            yield handleIndicatorUpsert(context, data);
        }
        if (entityType === STIX_SIGHTING_RELATIONSHIP) {
            yield handleIndicatorRelationUpsert(context, data);
        }
    });
    // Contract
    const clean = (element, deletedDependencies) => __awaiter(void 0, void 0, void 0, function* () {
        yield deleteInferredRuleElement(def.id, element, deletedDependencies);
    });
    const insert = (element) => __awaiter(void 0, void 0, void 0, function* () {
        return applyUpsert(element);
    });
    const update = (element) => __awaiter(void 0, void 0, void 0, function* () {
        return applyUpsert(element);
    });
    return Object.assign(Object.assign({}, def), { insert, update, clean });
};
const RuleSightingIncident = ruleSightingIncidentBuilder();
export default RuleSightingIncident;
