import type { JSONSchemaType } from 'ajv';
import * as jsonpatch from 'fast-json-patch';
import { type PlaybookComponent } from '../playbook-types';
import { INPUT_AUTHORIZED_MEMBERS } from '../../../schema/general';
import { generateInternalType } from '../../../schema/schemaUtils';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { isNotEmptyField } from '../../../database/utils';
import { EditOperation } from '../../../generated/graphql';
import { AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES } from '../../../utils/authorizedMembers';
import { applyOperationFieldPatch } from '../playbook-utils';

export interface RemoveAccessRestrictionsConfiguration {
  all: boolean;
}
const PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA: JSONSchemaType<RemoveAccessRestrictionsConfiguration> = {
  type: 'object',
  properties: {
    all: { type: 'boolean', $ref: 'Remove access restrictions on all elements included in the bundle', default: false },
  },
  required: [],
};
export const PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT: PlaybookComponent<RemoveAccessRestrictionsConfiguration> = {
  id: 'PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT',
  name: 'Remove access restrictions',
  description: 'Remove advanced access restrictions on entities',
  icon: 'lock-remove',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const { all } = playbookNode.configuration;
    const patchOperations = [];
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const element = bundle.objects[index];
      const internalType = generateInternalType(element);
      if (AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES.includes(internalType) && (all || element.id === dataInstanceId)) {
        const patchValue = {
          op: EditOperation.Replace,
          path: `/objects/${index}/extensions/${STIX_EXT_OCTI}/restricted_members`,
          value: [],
        };
        const patchOperation = {
          operation: EditOperation.Replace,
          key: INPUT_AUTHORIZED_MEMBERS,
          value: [],
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
