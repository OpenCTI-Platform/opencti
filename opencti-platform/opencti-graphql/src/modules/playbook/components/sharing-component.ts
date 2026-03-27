import type { JSONSchemaType } from 'ajv';
import { playbookBundleElementsToApply, type PlaybookBundleElementsToApply, type PlaybookComponent } from '../playbook-types';
import { executionContext, SYSTEM_USER } from '../../../utils/access';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { internalFindByIds } from '../../../database/middleware-loader';
import { type BasicStoreEntityOrganization, ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../organization/organization-types';
import { isBundleElementInScope } from '../playbook-utils';

export interface SharingConfiguration {
  organizations: string[] | { label: string; value: string }[];
  applyToElements: PlaybookBundleElementsToApply;
}
const PLAYBOOK_SHARING_COMPONENT_SCHEMA: JSONSchemaType<SharingConfiguration> = {
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
export const PLAYBOOK_SHARING_COMPONENT: PlaybookComponent<SharingConfiguration> = {
  id: 'PLAYBOOK_SHARING_COMPONENT',
  name: 'Share with organizations',
  description: 'Share with organizations within the platform',
  icon: 'organization-add',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_SHARING_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_SHARING_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
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

    const bundleElementsToApply = bundle.objects.filter((object) => isBundleElementInScope(object, applyToElements, dataInstanceId));

    const organizationIds = organizationsByIds.map((o) => o.standard_id);
    for (let index = 0; index < bundleElementsToApply.length; index += 1) {
      const element = bundleElementsToApply[index];
      element.extensions[STIX_EXT_OCTI].granted_refs = [...(element.extensions[STIX_EXT_OCTI].granted_refs ?? []), ...organizationIds];
    }

    return { output_port: 'out', bundle };
  },
};
