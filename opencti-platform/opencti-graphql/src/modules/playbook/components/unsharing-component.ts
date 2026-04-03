import type { JSONSchemaType } from 'ajv';
import * as jsonpatch from 'fast-json-patch';
import { playbookBundleElementsToApply, type PlaybookBundleElementsToApply, type PlaybookComponent } from '../playbook-types';
import { AUTOMATION_MANAGER_USER, executionContext, SYSTEM_USER } from '../../../utils/access';
import { INPUT_GRANTED_REFS } from '../../../schema/general';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { internalFindByIds } from '../../../database/middleware-loader';
import { type BasicStoreEntityOrganization, ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../organization/organization-types';
import { isNotEmptyField } from '../../../database/utils';
import { EditOperation } from '../../../generated/graphql';
import { applyOperationFieldPatch, isBundleElementInScope } from '../playbook-utils';

export interface UnsharingConfiguration {
  organizations: string[] | { label: string; value: string }[];
  applyToElements: PlaybookBundleElementsToApply;
}
const PLAYBOOK_UNSHARING_COMPONENT_SCHEMA: JSONSchemaType<UnsharingConfiguration> = {
  type: 'object',
  properties: {
    organizations: {
      type: 'array',
      uniqueItems: true,
      default: [],
      $ref: 'Target organizations',
      items: { type: 'string', oneOf: [] },
    },
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
  },
  required: ['organizations', 'applyToElements'],
};
export const PLAYBOOK_UNSHARING_COMPONENT: PlaybookComponent<UnsharingConfiguration> = {
  id: 'PLAYBOOK_UNSHARING_COMPONENT',
  name: 'Unshare with organizations',
  description: 'Unshare with organizations within the platform',
  icon: 'organization-remove',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_UNSHARING_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_UNSHARING_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components', AUTOMATION_MANAGER_USER);
    const { organizations, applyToElements } = playbookNode.configuration;
    const organizationsValues = organizations.map((o) => (typeof o !== 'string' ? o.value : o));
    const organizationsByIds = await internalFindByIds<BasicStoreEntityOrganization>(context, SYSTEM_USER, organizationsValues, {
      type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
      baseData: true,
      baseFields: ['standard_id'],
    }) as BasicStoreEntityOrganization[];
    if (organizationsByIds.length === 0) {
      return { output_port: 'out', bundle }; // nothing to do since organizations are empty
    }
    const organizationIds = organizationsByIds.map((o) => o.standard_id);
    const patchOperations = [];
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const element = bundle.objects[index];
      if (isBundleElementInScope(element, applyToElements, dataInstanceId)) {
        const patchValue = {
          op: EditOperation.Remove,
          path: `/objects/${index}/extensions/${STIX_EXT_OCTI}/granted_refs`,
          value: organizationIds,
        };
        const patchOperation = {
          operation: patchValue.op,
          key: INPUT_GRANTED_REFS,
          value: patchValue.value,
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
