import type { ImportContext } from './context';
import { StixImportError, UploadFile } from './types';
import { basename, isMissing, iterate } from './utils';

// Calls the operations make on knowledge (pycti/entities: opencti_stix_core_object.py,
// opencti_stix_core_relationship.py, opencti_stix_sighting_relationship.py,
// opencti_stix_domain_object.py, opencti_stix_cyber_observable.py, opencti_indicator.py,
// opencti_external_reference.py, opencti_security_coverage.py, opencti_stix.py).
// pycti app_logger.info lines are not ported.

// region stix core object
const STIX_CORE_OBJECT_DELETE = `
  mutation StixCoreObjectEdit($id: ID!) {
    stixCoreObjectEdit(id: $id) { delete }
  }
`;
const STIX_CORE_OBJECT_DRAFT_REMOVE = `
  mutation StixCoreObjectEditDraftRemove($id: ID!) {
    stixCoreObjectEdit(id: $id) { removeFromDraft }
  }
`;
const STIX_CORE_APPLY_RULE = `
  mutation StixCoreApplyRule($elementId: ID!, $ruleId: ID!, $executionId: ID!) {
    ruleApplyAsync(elementId: $elementId, ruleId: $ruleId, executionId: $executionId)
  }
`;
const STIX_CORE_CLEAR_RULE = `
  mutation StixCoreClearRule($elementId: ID!, $ruleId: ID!) {
    ruleClear(elementId: $elementId, ruleId: $ruleId)
  }
`;
// pycti's document declares no $executionId and is not valid GraphQL: this is the intended one
const STIX_CORE_RESCAN_RULES = `
  mutation StixCoreRescanRules($elementId: ID!, $executionId: ID!) {
    rulesRescanAsync(elementId: $elementId, executionId: $executionId)
  }
`;
const STIX_CORE_OBJECT_CLEAR_ACCESS_RESTRICTION = `
  mutation StixCoreObjectEdit($id: ID!) {
    stixCoreObjectEdit(id: $id) { clearAccessRestriction { id } }
  }
`;
const STIX_CORE_OBJECT_ASK_ENRICHMENTS = `
  mutation StixCoreObjectEdit($id: ID!, $connectorIds: [ID!]!) {
    stixCoreObjectEdit(id: $id) { askEnrichments(connectorIds: $connectorIds) { id } }
  }
`;
const STIX_CORE_OBJECT_SHARE = `
  mutation StixCoreObjectEdit($id: ID!, $organizationId: [ID!]!, $directContainerSharing: Boolean) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationAdd(organizationId: $organizationId, directContainerSharing: $directContainerSharing) { id }
    }
  }
`;
const STIX_CORE_OBJECT_UNSHARE = `
  mutation StixCoreObjectEdit($id: ID!, $organizationId: [ID!]!, $directContainerSharing: Boolean) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationDelete(organizationId: $organizationId, directContainerSharing: $directContainerSharing) { id }
    }
  }
`;

// pycti stix_core_object.delete
export const deleteStixCoreObject = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.error('[opencti_stix_core_object] Missing parameters: id');
    return;
  }
  await context.client.query(STIX_CORE_OBJECT_DELETE, { id });
};

// pycti stix_core_object.remove_from_draft
export const removeStixCoreObjectFromDraft = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.error('[stix_core_object] Cannot remove from draft, missing parameters: id');
    return;
  }
  await context.client.query(STIX_CORE_OBJECT_DRAFT_REMOVE, { id });
};

// pycti asks again until the platform reports completion, without a bound: a platform that never
// completes would hold the importer forever. Bounded here; past the bound, logged and given up
const RULE_MAX_ATTEMPTS = 1000;

const askUntilComplete = async (context: ImportContext, document: string, variables: Record<string, unknown>, field: string) => {
  for (let attempt = 0; attempt < RULE_MAX_ATTEMPTS; attempt += 1) {
    const data = await context.client.query(document, variables);
    if (data[field]) {
      return;
    }
  }
  context.logger.error(`[stix_core_object] ${field} not complete after ${RULE_MAX_ATTEMPTS} attempts, given up`);
};

// pycti stix_core_object.rule_apply_async: asks again until the platform reports completion
export const ruleApplyAsync = async (context: ImportContext, elementId: string | null, ruleId: string | null, executionId: string | null) => {
  if (isMissing(elementId) || isMissing(ruleId) || isMissing(executionId)) {
    context.logger.error('[stix_core_object] Cannot apply rule, missing parameters: id');
    return;
  }
  await askUntilComplete(context, STIX_CORE_APPLY_RULE, { elementId, ruleId, executionId }, 'ruleApplyAsync');
};

// pycti stix_core_object.rule_clear
export const ruleClear = async (context: ImportContext, elementId: string | null, ruleId: string | null) => {
  if (isMissing(elementId) || isMissing(ruleId)) {
    context.logger.error('[stix_core_object] Cannot clear rule, missing parameters: id');
    return;
  }
  await context.client.query(STIX_CORE_CLEAR_RULE, { elementId, ruleId });
};

// pycti stix_core_object.rule_rescan_async: asks again until the platform reports completion
export const ruleRescanAsync = async (context: ImportContext, elementId: string | null, executionId: string | null) => {
  if (isMissing(elementId) || isMissing(executionId)) {
    context.logger.error('[stix_core_object] Cannot rescan rule, missing parameters: id');
    return;
  }
  await askUntilComplete(context, STIX_CORE_RESCAN_RULES, { elementId, executionId }, 'rulesRescanAsync');
};

// pycti stix_core_object.clear_access_restriction
export const clearAccessRestriction = async (context: ImportContext, elementId: string | null) => {
  if (isMissing(elementId)) {
    context.logger.error('[stix_core_object] Cannot clear access restriction, missing parameters: id');
    return;
  }
  await context.client.query(STIX_CORE_OBJECT_CLEAR_ACCESS_RESTRICTION, { id: elementId });
};

// pycti stix_core_object.ask_enrichments
export const askEnrichments = async (context: ImportContext, elementId: string | null, connectorIds: unknown) => {
  await context.client.query(STIX_CORE_OBJECT_ASK_ENRICHMENTS, { id: elementId, connectorIds });
};

// pycti stix_core_object.organization_share
export const shareStixCoreObject = async (context: ImportContext, entityId: string, organizationIds: unknown, sharingDirectContainer: unknown) => {
  await context.client.query(STIX_CORE_OBJECT_SHARE, { id: entityId, organizationId: organizationIds, directContainerSharing: sharingDirectContainer });
};

// pycti stix_core_object.organization_unshare
export const unshareStixCoreObject = async (context: ImportContext, entityId: string, organizationIds: unknown, sharingDirectContainer: unknown) => {
  await context.client.query(STIX_CORE_OBJECT_UNSHARE, { id: entityId, organizationId: organizationIds, directContainerSharing: sharingDirectContainer });
};
// endregion

// region stix core relationship
const STIX_CORE_RELATIONSHIP_FIELD_PATCH = `
  mutation StixCoreRelationshipEdit($id: ID!, $input: [EditInput]!) {
    stixCoreRelationshipEdit(id: $id) { fieldPatch(input: $input) { id standard_id entity_type } }
  }
`;
const STIX_CORE_RELATIONSHIP_DELETE = `
  mutation StixCoreRelationshipEdit($id: ID!) {
    stixCoreRelationshipEdit(id: $id) { delete }
  }
`;
const STIX_CORE_RELATIONSHIP_SHARE = `
  mutation StixCoreRelationshipEdit($id: ID!, $organizationId: [ID!]!, $directContainerSharing: Boolean) {
    stixCoreRelationshipEdit(id: $id) { restrictionOrganizationAdd(organizationId: $organizationId, directContainerSharing: $directContainerSharing) { id } }
  }
`;
const STIX_CORE_RELATIONSHIP_UNSHARE = `
  mutation StixCoreRelationshipEdit($id: ID!, $organizationId: [ID!]!, $directContainerSharing: Boolean) {
    stixCoreRelationshipEdit(id: $id) { restrictionOrganizationDelete(organizationId: $organizationId, directContainerSharing: $directContainerSharing) { id } }
  }
`;
const STIX_CORE_RELATIONSHIP_DRAFT_REMOVE = `
  mutation StixCoreRelationshipEditDraftRemove($id: ID!) {
    stixCoreRelationshipEdit(id: $id) { removeFromDraft }
  }
`;

// pycti stix_core_relationship.update_field
export const updateStixCoreRelationshipField = async (context: ImportContext, id: string | null, input: unknown) => {
  if (isMissing(id) || isMissing(input)) {
    context.logger.error('[opencti_stix_core_relationship] Missing parameters: id and input');
    return;
  }
  await context.client.query(STIX_CORE_RELATIONSHIP_FIELD_PATCH, { id, input });
};

// pycti stix_core_relationship.delete
export const deleteStixCoreRelationship = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.error('[opencti_stix_core_relationship] Missing parameters: id');
    return;
  }
  await context.client.query(STIX_CORE_RELATIONSHIP_DELETE, { id });
};

// pycti stix_core_relationship.organization_share
export const shareStixCoreRelationship = async (context: ImportContext, entityId: string, organizationIds: unknown, sharingDirectContainer: unknown) => {
  await context.client.query(STIX_CORE_RELATIONSHIP_SHARE, { id: entityId, organizationId: organizationIds, directContainerSharing: sharingDirectContainer });
};

// pycti stix_core_relationship.organization_unshare
export const unshareStixCoreRelationship = async (context: ImportContext, entityId: string, organizationIds: unknown, sharingDirectContainer: unknown) => {
  await context.client.query(STIX_CORE_RELATIONSHIP_UNSHARE, { id: entityId, organizationId: organizationIds, directContainerSharing: sharingDirectContainer });
};

// pycti stix_core_relationship.remove_from_draft
export const removeStixCoreRelationshipFromDraft = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.error('[stix_core_relationship] Cannot remove from draft, missing parameters: id');
    return;
  }
  await context.client.query(STIX_CORE_RELATIONSHIP_DRAFT_REMOVE, { id });
};
// endregion

// region stix sighting relationship
const STIX_SIGHTING_FIELD_PATCH = `
  mutation StixSightingRelationshipEdit($id: ID!, $input: [EditInput]!) {
    stixSightingRelationshipEdit(id: $id) { fieldPatch(input: $input) { id } }
  }
`;
const STIX_SIGHTING_DELETE = `
  mutation StixSightingRelationshipEdit($id: ID!) {
    stixSightingRelationshipEdit(id: $id) { delete }
  }
`;
const STIX_SIGHTING_SHARE = `
  mutation StixSightingRelationshipEdit($id: ID!, $organizationId: [ID!]!, $directContainerSharing: Boolean) {
    stixSightingRelationshipEdit(id: $id) {
      restrictionOrganizationAdd(organizationId: $organizationId, directContainerSharing: $directContainerSharing) { id }
    }
  }
`;
const STIX_SIGHTING_UNSHARE = `
  mutation StixSightingRelationshipEdit($id: ID!, $organizationId: [ID!]!, $directContainerSharing: Boolean) {
    stixSightingRelationshipEdit(id: $id) {
      restrictionOrganizationDelete(organizationId: $organizationId, directContainerSharing: $directContainerSharing) { id }
    }
  }
`;
const STIX_SIGHTING_DRAFT_REMOVE = `
  mutation StixSightingRelationshipEditDraftRemove($id: ID!) {
    stixSightingRelationshipEdit(id: $id) { removeFromDraft }
  }
`;

// pycti stix_sighting_relationship.update_field
export const updateStixSightingField = async (context: ImportContext, id: string | null, input: unknown) => {
  if (isMissing(id) || isMissing(input)) {
    context.logger.error('[opencti_stix_sighting] Missing parameters: id and input');
    return;
  }
  await context.client.query(STIX_SIGHTING_FIELD_PATCH, { id, input });
};

// pycti stix_sighting_relationship.delete
export const deleteStixSighting = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.error('[opencti_stix_sighting] Missing parameters: id');
    return;
  }
  await context.client.query(STIX_SIGHTING_DELETE, { id });
};

// pycti stix_sighting_relationship.organization_share
export const shareStixSighting = async (context: ImportContext, entityId: string, organizationIds: unknown, sharingDirectContainer: unknown) => {
  await context.client.query(STIX_SIGHTING_SHARE, { id: entityId, organizationId: organizationIds, directContainerSharing: sharingDirectContainer });
};

// pycti stix_sighting_relationship.organization_unshare
export const unshareStixSighting = async (context: ImportContext, entityId: string, organizationIds: unknown, sharingDirectContainer: unknown) => {
  await context.client.query(STIX_SIGHTING_UNSHARE, { id: entityId, organizationId: organizationIds, directContainerSharing: sharingDirectContainer });
};

// pycti stix_sighting_relationship.remove_from_draft
export const removeStixSightingFromDraft = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.error('[stix_sighting] Cannot remove from draft, missing parameters: id');
    return;
  }
  await context.client.query(STIX_SIGHTING_DRAFT_REMOVE, { id });
};
// endregion

// region field patches and files of the other knowledge
const STIX_DOMAIN_OBJECT_FIELD_PATCH = `
  mutation StixDomainObjectEdit($id: ID!, $input: [EditInput]!) {
    stixDomainObjectEdit(id: $id) { fieldPatch(input: $input) { id standard_id entity_type } }
  }
`;
const STIX_CYBER_OBSERVABLE_FIELD_PATCH = `
  mutation StixCyberObservableEdit($id: ID!, $input: [EditInput]!) {
    stixCyberObservableEdit(id: $id) { fieldPatch(input: $input) { id standard_id entity_type } }
  }
`;
const EXTERNAL_REFERENCE_FIELD_PATCH = `
  mutation ExternalReferenceEdit($id: ID!, $input: [EditInput]!) {
    externalReferenceEdit(id: $id) { fieldPatch(input: $input) { id } }
  }
`;
const INDICATOR_FIELD_PATCH = `
  mutation IndicatorFieldPatch($id: ID!, $input: [EditInput!]!) {
    indicatorFieldPatch(id: $id, input: $input) { id standard_id entity_type }
  }
`;
const STIX_DOMAIN_OBJECT_IMPORT_PUSH = `
  mutation StixDomainObjectEdit($id: ID!, $file: Upload!, $fileMarkings: [String], $version: DateTime, $noTriggerImport: Boolean, $embedded: Boolean) {
    stixDomainObjectEdit(id: $id) {
      importPush(file: $file, version: $version, fileMarkings: $fileMarkings, noTriggerImport: $noTriggerImport, embedded: $embedded) { id name }
    }
  }
`;
const STIX_CYBER_OBSERVABLE_IMPORT_PUSH = `
  mutation StixCyberObservableEdit($id: ID!, $file: Upload!, $fileMarkings: [String], $version: DateTime, $noTriggerImport: Boolean, $embedded: Boolean) {
    stixCyberObservableEdit(id: $id) {
      importPush(file: $file, version: $version, fileMarkings: $fileMarkings, noTriggerImport: $noTriggerImport, embedded: $embedded) { id name }
    }
  }
`;
const EXTERNAL_REFERENCE_IMPORT_PUSH = `
  mutation ExternalReferenceEdit($id: ID!, $file: Upload!, $fileMarkings: [String], $version: DateTime, $noTriggerImport: Boolean, $embedded: Boolean) {
    externalReferenceEdit(id: $id) {
      importPush(file: $file, fileMarkings: $fileMarkings, version: $version, noTriggerImport: $noTriggerImport, embedded: $embedded) { id name }
    }
  }
`;

// pycti stix_domain_object.update_field
export const updateStixDomainObjectField = async (context: ImportContext, id: string | null, input: unknown) => {
  if (isMissing(id) || isMissing(input)) {
    context.logger.error('[opencti_stix_domain_object] Missing parameters: id and input');
    return;
  }
  await context.client.query(STIX_DOMAIN_OBJECT_FIELD_PATCH, { id, input });
};

// pycti stix_cyber_observable.update_field
export const updateStixCyberObservableField = async (context: ImportContext, id: string | null, input: unknown) => {
  if (isMissing(id) || isMissing(input)) {
    context.logger.error('[opencti_stix_cyber_observable_update_field] Missing parameters: id and input');
    return;
  }
  await context.client.query(STIX_CYBER_OBSERVABLE_FIELD_PATCH, { id, input });
};

// pycti external_reference.update_field
export const updateExternalReferenceField = async (context: ImportContext, id: string | null, input: unknown) => {
  if (isMissing(id) || isMissing(input)) {
    context.logger.error('[opencti_external_reference] Missing parameters: id and key and value');
    return;
  }
  await context.client.query(EXTERNAL_REFERENCE_FIELD_PATCH, { id, input });
};

// pycti indicator.update_field
export const updateIndicatorField = async (context: ImportContext, id: string | null, input: unknown) => {
  if (isMissing(id) || isMissing(input)) {
    context.logger.error('[opencti_indicator] Cannot update indicator field, missing parameters: id and input');
    return;
  }
  await context.client.query(INDICATOR_FIELD_PATCH, { id, input });
};

export interface AddFileArguments {
  id: string | null;
  fileName: string | null;
  data: Buffer;
  version: unknown;
  fileMarkings: unknown;
  // pycti passes mime_type explicitly, so add_file's "text/plain" default never applies
  mimeType: string | null;
  noTriggerImport: unknown;
  embedded: unknown;
}

// The add_file methods of pycti (stix_domain_object, stix_cyber_observable, external_reference)
// with the data given: the same body, only the document and the error message differ
const addFile = async (context: ImportContext, document: string, missingMessage: string, args: AddFileArguments) => {
  if (isMissing(args.id) || isMissing(args.fileName)) {
    context.logger.error(missingMessage);
    return;
  }
  const finalFileName = basename(args.fileName);
  await context.client.query(document, {
    id: args.id,
    file: new UploadFile(finalFileName, args.data, args.mimeType as string),
    fileMarkings: args.fileMarkings,
    version: args.version,
    noTriggerImport: typeof args.noTriggerImport === 'boolean' ? args.noTriggerImport : args.noTriggerImport === 'True',
    embedded: args.embedded,
  });
};

// pycti stix_domain_object.add_file
export const addStixDomainObjectFile = (context: ImportContext, args: AddFileArguments) => {
  return addFile(context, STIX_DOMAIN_OBJECT_IMPORT_PUSH, '[opencti_stix_domain_object] Missing parameters: id or file_name', args);
};

// pycti stix_cyber_observable.add_file
export const addStixCyberObservableFile = (context: ImportContext, args: AddFileArguments) => {
  return addFile(context, STIX_CYBER_OBSERVABLE_IMPORT_PUSH, '[opencti_stix_cyber_observable] Missing parameters: id or file_name', args);
};

// pycti external_reference.add_file
export const addExternalReferenceFile = (context: ImportContext, args: AddFileArguments) => {
  return addFile(context, EXTERNAL_REFERENCE_IMPORT_PUSH, '[opencti_external_reference] Missing parameters: id or file_name', args);
};
// endregion

// region deletes and merge of the other knowledge
const STIX_CYBER_OBSERVABLE_DELETE = `
  mutation StixCyberObservableEdit($id: ID!) {
    stixCyberObservableEdit(id: $id) { delete }
  }
`;
const EXTERNAL_REFERENCE_DELETE = `
  mutation ExternalReferenceEdit($id: ID!) {
    externalReferenceEdit(id: $id) { delete }
  }
`;
const SECURITY_COVERAGE_DELETE = `
  mutation SecurityCoverageDelete($id: ID!) {
    securityCoverageDelete(id: $id)
  }
`;
const STIX_DELETE = `
  mutation StixEdit($id: ID!, $forceDelete: Boolean) {
    stixEdit(id: $id) { delete(forceDelete: $forceDelete) }
  }
`;
const STIX_MERGE = `
  mutation StixEdit($id: ID!, $stixObjectsIds: [String]!) {
    stixEdit(id: $id) { merge(stixObjectsIds: $stixObjectsIds) { id standard_id entity_type } }
  }
`;

// pycti stix_cyber_observable.delete
export const deleteStixCyberObservable = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.error('[opencti_stix_cyber_observable_delete] Missing parameters: id');
    return;
  }
  await context.client.query(STIX_CYBER_OBSERVABLE_DELETE, { id });
};

// pycti external_reference.delete (no check of the id)
export const deleteExternalReference = async (context: ImportContext, id: string) => {
  await context.client.query(EXTERNAL_REFERENCE_DELETE, { id });
};

// pycti security_coverage.delete
export const deleteSecurityCoverage = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.error('[opencti_security_coverage] Missing parameters: id');
    return;
  }
  await context.client.query(SECURITY_COVERAGE_DELETE, { id });
};

// pycti stix.delete
export const deleteStix = async (context: ImportContext, id: string | null, forceDelete = true) => {
  if (isMissing(id)) {
    context.logger.error('[opencti_stix] Missing parameters: id');
    return;
  }
  await context.client.query(STIX_DELETE, { id, forceDelete });
};

// pycti stix.merge
export const mergeStix = async (context: ImportContext, id: unknown, objectIds: unknown) => {
  if (isMissing(id) || isMissing(objectIds)) {
    context.logger.error('[opencti_stix] Missing parameters: id and object_ids');
    return;
  }
  // pycti logs `",".join(stix_objects_ids)` first: any iterable of str (a list, a str, the keys
  // of a dict), anything else fails
  if (!iterate(objectIds).every((objectId) => typeof objectId === 'string')) {
    throw new StixImportError('TypeError', 'sequence item: expected str instance');
  }
  await context.client.query(STIX_MERGE, { id, stixObjectsIds: objectIds });
};
// endregion
