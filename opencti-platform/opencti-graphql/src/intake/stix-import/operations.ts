import { field } from './kwargs';
import { STIX_CORE_OBJECTS, STIX_CYBER_OBSERVABLE_TYPES, STIX_META_OBJECTS } from '../../utils/stix2-splitter';
import type { ImportContext } from './context';
import { createStixCoreRelationship } from './relationships';
import {
  addExternalReferenceFile,
  type AddFileArguments,
  addStixCyberObservableFile,
  addStixDomainObjectFile,
  askEnrichments,
  clearAccessRestriction,
  deleteExternalReference,
  deleteSecurityCoverage,
  deleteStix,
  deleteStixCoreObject,
  deleteStixCoreRelationship,
  deleteStixCyberObservable,
  deleteStixSighting,
  mergeStix,
  removeStixCoreObjectFromDraft,
  removeStixCoreRelationshipFromDraft,
  removeStixSightingFromDraft,
  ruleApplyAsync,
  ruleClear,
  ruleRescanAsync,
  shareStixCoreObject,
  shareStixCoreRelationship,
  shareStixSighting,
  unshareStixCoreObject,
  unshareStixCoreRelationship,
  unshareStixSighting,
  updateExternalReferenceField,
  updateIndicatorField,
  updateStixCoreRelationshipField,
  updateStixCyberObservableField,
  updateStixDomainObjectField,
  updateStixSightingField,
} from './operations-knowledge';
import {
  addUserMembership,
  addUserOrganization,
  deleteUserMembership,
  deleteUserOrganization,
  executePlaybook,
  INTERNAL_DELETES,
  pirFlagElement,
  pirUnflagElement,
  restoreDeleteOperation,
  sendUserMail,
  updateNotificationField,
  updateUserField,
} from './operations-internal';
import { StixImportError, type StixObject } from './types';
import {
  b64decode,
  contains,
  convertMarkdown,
  dictGet,
  first,
  getAttributeInExtension,
  isStixCyberObservableType,
  iterate,
  pythonTruthy,
  pythonType,
  required,
  tableGet,
} from './utils';

// pycti OpenCTIStix2.apply_opencti_operation and the methods it calls (pycti/utils/opencti_stix2.py):
// an object carrying an `opencti_operation` (a task of the platform, a stream event) to the
// GraphQL operation it asks for.

// pycti `type in STIX_CYBER_OBSERVABLE_MAPPING`: the keys are the observable types in lower case,
// compared case sensitively (unlike StixCyberObservableTypes.has_value)
const isObservableMappingKey = (type: unknown) => {
  if (type !== null && typeof type === 'object') {
    throw new StixImportError('TypeError', `unhashable type: '${pythonType(type)}'`);
  }
  return typeof type === 'string' && STIX_CYBER_OBSERVABLE_TYPES.includes(type);
};

// The pycti pattern `value = get_attribute_in_extension(key, item); if value is None: value = item[key]`
const extensionOrItem = (item: StixObject, key: string) => {
  const value = getAttributeInExtension(key, item);
  return value === null ? required(item, key) : value;
};

// pycti OpenCTIStix2.apply_patch_files
const applyPatchFiles = async (context: ImportContext, item: StixObject) => {
  const fieldPatch = extensionOrItem(item, 'opencti_field_patch');
  const fieldPatchFiles = iterate(fieldPatch).find((patch) => required(patch as StixObject, 'key') === 'x_opencti_files') as StixObject | undefined;
  const itemId = extensionOrItem(item, 'id');
  let doAddFile = addStixDomainObjectFile;
  if (isStixCyberObservableType(item.type)) {
    doAddFile = addStixCyberObservableFile;
  } else if (item.type === 'external-reference') {
    doAddFile = addExternalReferenceFile;
  }
  if (fieldPatchFiles !== undefined) {
    for (const file of iterate(required(fieldPatchFiles, 'value')) as StixObject[]) {
      if (contains(file, 'data')) {
        const args: AddFileArguments = {
          id: itemId,
          fileName: required(file, 'name'),
          version: dictGet(file, 'version'),
          data: b64decode(file.data),
          fileMarkings: dictGet(file, 'object_marking_refs'),
          mimeType: dictGet(file, 'mime_type'),
          noTriggerImport: field(file, 'no_trigger_import', false),
          embedded: field(file, 'embedded', false),
        };
        await doAddFile(context, args);
      }
    }
  }
};

// pycti OpenCTIStix2.apply_patch
const applyPatch = async (context: ImportContext, item: StixObject) => {
  const fieldPatch = extensionOrItem(item, 'opencti_field_patch');
  const fieldPatchWithoutFiles = iterate(fieldPatch).filter((patch) => required(patch as StixObject, 'key') !== 'x_opencti_files');
  const itemId = extensionOrItem(item, 'id');
  if (fieldPatchWithoutFiles.length > 0) {
    if (item.type === 'relationship') {
      await updateStixCoreRelationshipField(context, itemId, fieldPatchWithoutFiles);
    } else if (item.type === 'sighting') {
      await updateStixSightingField(context, itemId, fieldPatchWithoutFiles);
    } else if (isStixCyberObservableType(item.type)) {
      await updateStixCyberObservableField(context, itemId, fieldPatchWithoutFiles);
    } else if (item.type === 'external-reference') {
      await updateExternalReferenceField(context, itemId, fieldPatchWithoutFiles);
    } else if (item.type === 'indicator') {
      await updateIndicatorField(context, itemId, fieldPatchWithoutFiles);
    } else if (item.type === 'notification') {
      await updateNotificationField(context, itemId, fieldPatchWithoutFiles);
    } else if (item.type === 'user') {
      await updateUserField(context, itemId, fieldPatchWithoutFiles);
    } else {
      await updateStixDomainObjectField(context, itemId, fieldPatchWithoutFiles);
    }
  }
  await applyPatchFiles(context, item);
};

// pycti OpenCTIStix2.rule_apply
const applyRule = async (context: ImportContext, item: StixObject, bundleId: string) => {
  const ruleId = extensionOrItem(item, 'opencti_rule');
  await ruleApplyAsync(context, item.id, ruleId, bundleId);
};

// pycti OpenCTIStix2.rule_clear
const clearRule = async (context: ImportContext, item: StixObject) => {
  const ruleId = extensionOrItem(item, 'opencti_rule');
  await ruleClear(context, item.id, ruleId);
};

// pycti OpenCTIStix2.rules_rescan. pycti calls stix_core_object.rules_rescan_async, which does
// not exist (AttributeError): the port calls the existing rule_rescan_async, as intended.
const rescanRules = async (context: ImportContext, item: StixObject, bundleId: string) => {
  await ruleRescanAsync(context, item.id, bundleId);
};

// pycti OpenCTIStix2.organization_share
const shareWithOrganizations = async (context: ImportContext, item: StixObject) => {
  const organizationIds = extensionOrItem(item, 'sharing_organization_ids');
  const sharingDirectContainer = extensionOrItem(item, 'sharing_direct_container');
  if (item.type === 'relationship') {
    await shareStixCoreRelationship(context, item.id, organizationIds, sharingDirectContainer);
  } else if (item.type === 'sighting') {
    await shareStixSighting(context, item.id, organizationIds, sharingDirectContainer);
  } else {
    // Element is considered stix core object
    await shareStixCoreObject(context, item.id, organizationIds, sharingDirectContainer);
  }
};

// pycti OpenCTIStix2.organization_unshare
const unshareWithOrganizations = async (context: ImportContext, item: StixObject) => {
  const organizationIds = extensionOrItem(item, 'sharing_organization_ids');
  const sharingDirectContainer = extensionOrItem(item, 'sharing_direct_container');
  if (item.type === 'relationship') {
    await unshareStixCoreRelationship(context, item.id, organizationIds, sharingDirectContainer);
  } else if (item.type === 'sighting') {
    await unshareStixSighting(context, item.id, organizationIds, sharingDirectContainer);
  } else {
    // Element is considered stix core object
    await unshareStixCoreObject(context, item.id, organizationIds, sharingDirectContainer);
  }
};

// pycti OpenCTIStix2.element_add_organizations
const addOrganizations = async (context: ImportContext, item: StixObject) => {
  const organizationIds = extensionOrItem(item, 'organization_ids');
  if (item.type !== 'user') {
    throw new StixImportError('ValueError', 'Add organizations operation not compatible with type', { type: item.type });
  }
  for (const organizationId of iterate(organizationIds)) {
    await addUserOrganization(context, item.id, organizationId);
  }
};

// pycti OpenCTIStix2.element_remove_organizations
const removeOrganizations = async (context: ImportContext, item: StixObject) => {
  const organizationIds = extensionOrItem(item, 'organization_ids');
  if (item.type !== 'user') {
    throw new StixImportError('ValueError', 'Remove organizations operation not compatible with type', { type: item.type });
  }
  for (const organizationId of iterate(organizationIds)) {
    await deleteUserOrganization(context, item.id, organizationId);
  }
};

// pycti OpenCTIStix2.element_add_groups
const addGroups = async (context: ImportContext, item: StixObject) => {
  const groupIds = extensionOrItem(item, 'group_ids');
  if (item.type !== 'user') {
    throw new StixImportError('ValueError', 'Add groups operation not compatible with type', { type: item.type });
  }
  for (const groupId of iterate(groupIds)) {
    await addUserMembership(context, item.id, groupId);
  }
};

// pycti OpenCTIStix2.element_remove_groups
const removeGroups = async (context: ImportContext, item: StixObject) => {
  const groupIds = extensionOrItem(item, 'group_ids');
  if (item.type !== 'user') {
    throw new StixImportError('ValueError', 'Remove groups operation not compatible with type', { type: item.type });
  }
  for (const groupId of iterate(groupIds)) {
    await deleteUserMembership(context, item.id, groupId);
  }
};

// pycti OpenCTIStix2.send_email
const sendEmail = async (context: ImportContext, item: StixObject) => {
  const templateId = extensionOrItem(item, 'template_id');
  if (item.type !== 'user') {
    throw new StixImportError('ValueError', 'Not supported opencti_operation for this type', { type: item.type });
  }
  await sendUserMail(context, item.id, first(templateId));
};

// pycti OpenCTIStix2.enroll_playbook
const enrollPlaybook = async (context: ImportContext, item: StixObject) => {
  let playbookId = getAttributeInExtension('playbook_id', item);
  if (playbookId === null) {
    playbookId = field(item, 'playbook_id');
  }
  let entityId = getAttributeInExtension('id', item);
  if (entityId === null) {
    entityId = field(item, 'id');
  }
  if (pythonTruthy(playbookId) && pythonTruthy(entityId)) {
    await executePlaybook(context, playbookId, entityId);
  }
};

// pycti OpenCTIStix2.element_operation_delete
const deleteElement = async (context: ImportContext, item: StixObject, operation: string) => {
  // If data is stix, just use the generic stix function for deletion
  const forceDelete = operation === 'delete_force';
  if (item.type === 'relationship') {
    await deleteStixCoreRelationship(context, item.id);
  } else if (item.type === 'external-reference') {
    await deleteExternalReference(context, item.id);
  } else if (item.type === 'sighting') {
    await deleteStixSighting(context, item.id);
  } else if (item.type === 'security-coverage') {
    await deleteSecurityCoverage(context, item.id);
  } else if (STIX_META_OBJECTS.includes(item.type)) {
    await deleteStix(context, item.id, forceDelete);
  } else if (isObservableMappingKey(item.type)) {
    await deleteStixCyberObservable(context, item.id);
  } else if (STIX_CORE_OBJECTS.includes(item.type)) {
    await deleteStixCoreObject(context, item.id);
  } else {
    // Element is not knowledge we need to use the right api
    const internalDelete = tableGet(INTERNAL_DELETES, item.type);
    if (!internalDelete) {
      throw new StixImportError('ValueError', 'Delete operation or not found stix helper', { type: item.type });
    }
    await internalDelete(context, item.id, item);
  }
};

// pycti OpenCTIStix2.element_remove_from_draft
const removeFromDraft = async (context: ImportContext, item: StixObject) => {
  if (item.type === 'relationship') {
    await removeStixCoreRelationshipFromDraft(context, item.id);
  } else if (item.type === 'sighting') {
    await removeStixSightingFromDraft(context, item.id);
  } else {
    // Element is considered stix core object
    await removeStixCoreObjectFromDraft(context, item.id);
  }
};

// The add_related_covered_entities branch of pycti apply_opencti_operation
const addRelatedCoveredEntities = async (context: ImportContext, item: StixObject) => {
  const securityCoverageResultId = getAttributeInExtension('security_coverage_result_id', item);
  const relationshipsConfig = getAttributeInExtension('relationships_config', item);
  const config = pythonTruthy(relationshipsConfig) ? relationshipsConfig : {};
  const rawCoverages = dictGet(config, 'coverage_information');
  const coverageInformation = iterate(pythonTruthy(rawCoverages) ? rawCoverages : []).filter((coverage) => contains(coverage, 'coverage_score'));
  const configValue = (key: string) => (contains(config, key) ? config[key] : null);
  await createStixCoreRelationship(context, {
    fromId: securityCoverageResultId,
    toId: item.id,
    relationship_type: 'has-covered',
    description: contains(config, 'description') ? convertMarkdown(config.description) : null,
    start_time: configValue('start_time'),
    stop_time: configValue('stop_time'),
    coverage_information: coverageInformation,
    confidence: configValue('confidence'),
    createdBy: configValue('createdBy'),
    objectMarking: configValue('objectMarking'),
    objectLabel: configValue('objectLabel'),
    externalReferences: configValue('externalReferences'),
  });
};

// pycti OpenCTIStix2.apply_opencti_operation
export const applyOpenctiOperation = async (context: ImportContext, item: StixObject, operation: string, bundleId: string) => {
  if (operation === 'delete' || operation === 'delete_force') {
    await deleteElement(context, item, operation);
  } else if (operation === 'revert_draft') {
    await removeFromDraft(context, item);
  } else if (operation === 'restore') {
    await restoreDeleteOperation(context, item.id);
  } else if (operation === 'enroll_playbook') {
    await enrollPlaybook(context, item);
  } else if (operation === 'merge') {
    const targetId = extensionOrItem(item, 'merge_target_id');
    const sourceIds = extensionOrItem(item, 'merge_source_ids');
    await mergeStix(context, targetId, sourceIds);
  } else if (operation === 'patch') {
    await applyPatch(context, item);
  } else if (operation === 'pir_flag_element') {
    await pirFlagElement(context, item.id, required(item, 'input'));
  } else if (operation === 'pir_unflag_element') {
    await pirUnflagElement(context, item.id, required(item, 'input'));
  } else if (operation === 'rule_apply') {
    await applyRule(context, item, bundleId);
  } else if (operation === 'rule_clear') {
    await clearRule(context, item);
  } else if (operation === 'rules_rescan') {
    await rescanRules(context, item, bundleId);
  } else if (operation === 'share') {
    await shareWithOrganizations(context, item);
  } else if (operation === 'unshare') {
    await unshareWithOrganizations(context, item);
  } else if (operation === 'clear_access_restriction') {
    await clearAccessRestriction(context, item.id);
  } else if (operation === 'add_related_covered_entities') {
    await addRelatedCoveredEntities(context, item);
  } else if (operation === 'enrichment') {
    const connectorIds = extensionOrItem(item, 'connector_ids');
    await askEnrichments(context, item.id, connectorIds);
  } else if (operation === 'add_organizations') {
    await addOrganizations(context, item);
  } else if (operation === 'remove_organizations') {
    await removeOrganizations(context, item);
  } else if (operation === 'add_groups') {
    await addGroups(context, item);
  } else if (operation === 'remove_groups') {
    await removeGroups(context, item);
  } else if (operation === 'send_email') {
    await sendEmail(context, item);
  } else {
    throw new StixImportError('ValueError', 'Not supported opencti_operation', { operation });
  }
};
