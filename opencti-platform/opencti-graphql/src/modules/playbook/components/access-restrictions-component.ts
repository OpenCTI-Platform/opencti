import type { JSONSchemaType } from 'ajv';
import * as jsonpatch from 'fast-json-patch';
import { playbookBundleElementsToApply, type PlaybookBundleElementsToApply, type PlaybookComponent } from '../playbook-types';
import { type AuthorizedMember, AUTOMATION_MANAGER_USER, executionContext } from '../../../utils/access';
import { ABSTRACT_STIX_DOMAIN_OBJECT, INPUT_AUTHORIZED_MEMBERS, OPENCTI_ADMIN_UUID } from '../../../schema/general';
import { generateInternalType } from '../../../schema/schemaUtils';
import type { StixObject } from '../../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../organization/organization-types';
import { isNotEmptyField } from '../../../database/utils';
import { EditOperation } from '../../../generated/graphql';
import { AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES, buildRestrictedMembers } from '../../../utils/authorizedMembers';
import { applyOperationFieldPatch, extractBundleBaseElement } from '../playbook-utils';

export interface AccessRestrictionsConfiguration {
  applyToElements: PlaybookBundleElementsToApply;
  access_restrictions: {
    groupsRestriction: {
      label: string;
      value: string;
      type: string;
    }[];
    accessRight: string;
    label: string;
    type: string;
    value: string;
  }[];
}
const PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA: JSONSchemaType<AccessRestrictionsConfiguration> = {
  type: 'object',
  properties: {
    applyToElements: {
      type: 'string',
      default: playbookBundleElementsToApply.onlyMain.value,
      $ref: 'Apply to',
      oneOf: [
        { const: playbookBundleElementsToApply.onlyMain.value, title: playbookBundleElementsToApply.onlyMain.title },
        { const: playbookBundleElementsToApply.allElements.value, title: playbookBundleElementsToApply.allElements.title },
        { const: playbookBundleElementsToApply.allExceptMain.value, title: playbookBundleElementsToApply.allExceptMain.title },
      ],
    },
    access_restrictions: {
      type: 'array',
      uniqueItems: true,
      default: [{
        label: 'Administrator',
        type: 'User',
        value: OPENCTI_ADMIN_UUID,
        accessRight: 'admin',
        groupsRestriction: [],
      }],
      $ref: 'Access restrictions',
      items: { type: 'object', oneOf: [] },
    },
  },
  required: ['access_restrictions', 'applyToElements'],
};
export const PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT: PlaybookComponent<AccessRestrictionsConfiguration> = {
  id: 'PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT',
  name: 'Manage access restrictions',
  description: 'Manage advanced access restrictions on entities',
  icon: 'lock',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const { access_restrictions: accessRestrictions, applyToElements } = playbookNode.configuration;
    // Resolve potential dynamic access rights
    const baseData = extractBundleBaseElement(dataInstanceId, bundle) as StixObject;
    const finalAccessRestrictions = [];
    for (let index = 0; index < accessRestrictions.length; index += 1) {
      const accessRestriction = accessRestrictions[index];
      if (accessRestriction.value === 'AUTHOR') {
        // If dynamic binding of author and an author is really defined in the data
        const createdById = baseData.extensions[STIX_EXT_OCTI].created_by_ref_id;
        const createdByType = baseData.extensions[STIX_EXT_OCTI].created_by_ref_type;
        if (isNotEmptyField(createdById) && createdByType === ENTITY_TYPE_IDENTITY_ORGANIZATION) {
          finalAccessRestrictions.push({ ...accessRestriction, value: createdById });
        }
      } else if (accessRestriction.value === 'CREATORS') {
        const creators = (baseData.extensions[STIX_EXT_OCTI].creator_ids ?? []).filter((id) => isNotEmptyField(id));
        for (let index2 = 0; index2 < creators.length; index2 += 1) {
          finalAccessRestrictions.push({ ...accessRestriction, value: creators[index2] });
        }
      } else if (accessRestriction.value === 'ASSIGNEES') {
        const assignees = (baseData.extensions[STIX_EXT_OCTI].assignee_ids ?? []).filter((id) => isNotEmptyField(id));
        for (let index2 = 0; index2 < assignees.length; index2 += 1) {
          finalAccessRestrictions.push({ ...accessRestriction, value: assignees[index2] });
        }
      } else if (accessRestriction.value === 'PARTICIPANTS') {
        const participants = (baseData.extensions[STIX_EXT_OCTI].participant_ids ?? []).filter((id) => isNotEmptyField(id));
        for (let index2 = 0; index2 < participants.length; index2 += 1) {
          finalAccessRestrictions.push({ ...accessRestriction, value: participants[index2] });
        }
      } else if (accessRestriction.value === 'BUNDLE_ORGANIZATIONS') {
        const bundleOrganizations = bundle.objects.filter((o) => o.extensions[STIX_EXT_OCTI].type === ENTITY_TYPE_IDENTITY_ORGANIZATION);
        const bundleOrganizationsIds = bundleOrganizations.map((o) => o.extensions[STIX_EXT_OCTI].id).filter((id) => isNotEmptyField(id));
        for (let index2 = 0; index2 < bundleOrganizationsIds.length; index2 += 1) {
          finalAccessRestrictions.push({ ...accessRestriction, value: bundleOrganizationsIds[index2] });
        }
      } else {
        finalAccessRestrictions.push(accessRestriction);
      }
    }
    const patchOperations = [];
    const input = finalAccessRestrictions.map((n) => ({
      id: n.value,
      access_right: n.accessRight,
      groups_restriction_ids: n.groupsRestriction.map((o) => o.value),
    }));
    if (input.length === 0) {
      return { output_port: 'out', bundle };
    }
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const element = bundle.objects[index];
      const internalType = generateInternalType(element);
      const all = applyToElements === playbookBundleElementsToApply.allElements.value;
      const onlyMain = applyToElements === playbookBundleElementsToApply.onlyMain.value && element.id === dataInstanceId;
      const exceptMain = applyToElements === playbookBundleElementsToApply.allExceptMain.value && element.id !== dataInstanceId;
      const shouldTakeObject = all || onlyMain || exceptMain;
      if (AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES.includes(internalType) && shouldTakeObject) {
        const args = {
          entityId: element.id,
          input,
          requiredCapabilities: ['KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS'],
          entityType: internalType,
          busTopicKey: ABSTRACT_STIX_DOMAIN_OBJECT,
        };
        const restrictedMembers = await buildRestrictedMembers(context, AUTOMATION_MANAGER_USER, args) as AuthorizedMember[];
        const patchValue = {
          op: EditOperation.Replace,
          path: `/objects/${index}/extensions/${STIX_EXT_OCTI}/authorized_members`,
          value: restrictedMembers,
        };
        const patchOperation = {
          operation: EditOperation.Replace,
          key: INPUT_AUTHORIZED_MEMBERS,
          value: restrictedMembers,
        };
        applyOperationFieldPatch(element, [patchOperation]);
        patchOperations.push(patchValue);
      }
    }
    if (patchOperations.length > 0) {
      const patchedBundle = jsonpatch.applyPatch(structuredClone(bundle), patchOperations).newDocument;
      const diff = jsonpatch.compare(bundle, patchedBundle);
      if (isNotEmptyField(diff)) {
        return { output_port: 'out', bundle: patchedBundle };
      }
    }
    return { output_port: 'out', bundle };
  },
};
