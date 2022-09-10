/* eslint-disable camelcase */
import type { Operation } from 'fast-json-patch';
import { createInferredRelation, deleteInferredRuleElement, } from '../../database/middleware';
import { RELATION_PART_OF } from '../../schema/stixCoreRelationship';
import def from './ReportIdentityDefinition';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { RELATION_OBJECT } from '../../schema/stixMetaRelationship';
import { createRuleContent, RULE_MANAGER_USER } from '../rules';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { generateInternalType } from '../../schema/schemaUtils';
import type { RuleRuntime } from '../../types/rules';
import type { StixObject } from '../../types/stix-common';
import type { StixReport } from '../../types/stix-sdo';
import type { StixRelation } from '../../types/stix-sro';
import type { BasicStoreEntity, BasicStoreRelation, StoreObject } from '../../types/store';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { listAllEntities, listAllRelations } from '../../database/middleware-loader';
import type { Event, UpdateEvent } from '../../types/event';

const ruleReportIdentityBuilder = (): RuleRuntime => {
  const handleReportCreation = async (report: StixReport) => {
    const events: Array<Event> = [];
    const { id: reportId } = report.extensions[STIX_EXT_OCTI];
    const { object_refs: reportObjectRefs } = report;
    // Get all identities from the report refs
    const identityRefs = reportObjectRefs.filter((ref) => {
      const [type] = ref.split('--');
      return type === ENTITY_TYPE_IDENTITY.toLowerCase();
    });
    // Find all identities part of current identities
    const listFromCallback = async (relationships: Array<BasicStoreRelation>) => {
      for (let relIndex = 0; relIndex < relationships.length; relIndex += 1) {
        const { internal_id: partOfId, fromId: partOfFromId, toId: partOfTargetId } = relationships[relIndex];
        const dependencies = [reportId, partOfFromId, partOfId, partOfTargetId];
        // Create the inferred relations
        const ruleRelationContent = createRuleContent(def.id, dependencies, [reportId, partOfId], {});
        const inputForRelation = { fromId: reportId, partOfId, relationship_type: RELATION_OBJECT };
        const eventForRelation = await createInferredRelation(inputForRelation, ruleRelationContent);
        if (eventForRelation) events.push(eventForRelation as Event);
        // -----------------------------------------------------------------------------------------------------------
        const ruleIdentityContent = createRuleContent(def.id, dependencies, [reportId, partOfTargetId], {});
        const inputForIdentity = { fromId: reportId, partOfTargetId, relationship_type: RELATION_OBJECT };
        const eventForIdentity = await createInferredRelation(inputForIdentity, ruleIdentityContent);
        if (eventForIdentity) events.push(eventForIdentity as Event);
      }
    };
    const listFromArgs = { fromId: identityRefs, toTypes: [ENTITY_TYPE_IDENTITY], callback: listFromCallback };
    await listAllRelations(RULE_MANAGER_USER, RELATION_PART_OF, listFromArgs);
    return events;
  };
  const handlePartOfRelationCreation = async (partOfRelation: StixRelation) => {
    const events: Array<Event> = [];
    const { id: partOfId, source_ref: partOfFromId, target_ref: partOfTargetId } = partOfRelation.extensions[STIX_EXT_OCTI];
    const listFromCallback = async (reports: Array<BasicStoreEntity>) => {
      for (let reportIndex = 0; reportIndex < reports.length; reportIndex += 1) {
        const { internal_id: reportId } = reports[reportIndex];
        const dependencies = [reportId, partOfFromId, partOfId, partOfTargetId];
        // Create the inferred relations
        const ruleRelationContent = createRuleContent(def.id, dependencies, [reportId, partOfId], {});
        const inputForRelation = { fromId: reportId, partOfId, relationship_type: RELATION_OBJECT };
        const eventForRelation = await createInferredRelation(inputForRelation, ruleRelationContent);
        if (eventForRelation) events.push(eventForRelation as Event);
        // -----------------------------------------------------------------------------------------------------------
        const ruleIdentityContent = createRuleContent(def.id, dependencies, [reportId, partOfTargetId], {});
        const inputForIdentity = { fromId: reportId, partOfTargetId, relationship_type: RELATION_OBJECT };
        const eventForIdentity = await createInferredRelation(inputForIdentity, ruleIdentityContent);
        if (eventForIdentity) events.push(eventForIdentity as Event);
      }
    };
    const listReportArgs = { fromTypes: [ENTITY_TYPE_CONTAINER_REPORT], toId: partOfFromId, callback: listFromCallback };
    await listAllEntities(RULE_MANAGER_USER, [ENTITY_TYPE_CONTAINER_REPORT], listReportArgs);
    return events;
  };
  const applyInsert = async (data: StixObject): Promise<Array<Event>> => {
    const events: Array<Event> = [];
    const entityType = generateInternalType(data);
    if (entityType === ENTITY_TYPE_CONTAINER_REPORT) {
      return handleReportCreation(data as StixReport);
    }
    const upsertRelation = data as StixRelation;
    const { relationship_type: relationType } = upsertRelation;
    if (relationType === RELATION_PART_OF) {
      return handlePartOfRelationCreation(upsertRelation);
    }
    return events;
  };
  const applyUpdate = async (data: StixObject, event: UpdateEvent): Promise<Array<Event>> => {
    const events: Array<Event> = [];
    const entityType = generateInternalType(data);
    if (entityType === ENTITY_TYPE_CONTAINER_REPORT) {
      const operations: Operation[] = event.context.patch;
      return events;
    }
    // We don't care about the relation update
    return events;
  };
  // Contract
  const clean = async (element: StoreObject, deletedDependencies: Array<string>): Promise<Array<Event>> => {
    const cleanPromiseEvents = deleteInferredRuleElement(def.id, element, deletedDependencies);
    return cleanPromiseEvents as unknown as Promise<Array<Event>>;
  };
  const insert = async (element: StixObject): Promise<Array<Event>> => applyInsert(element);
  const update = async (element: StixObject, event: UpdateEvent): Promise<Array<Event>> => applyUpdate(element, event);
  return { ...def, insert, update, clean };
};
const RuleReportIdentity = ruleReportIdentityBuilder();

export default RuleReportIdentity;
