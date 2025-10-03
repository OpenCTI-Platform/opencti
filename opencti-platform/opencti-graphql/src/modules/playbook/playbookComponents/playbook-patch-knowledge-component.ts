import type { JSONSchemaType } from 'ajv';
import * as jsonpatch from 'fast-json-patch';
import * as R from 'ramda';
import type { PlaybookComponent } from '../playbook-types';
import { AUTOMATION_MANAGER_USER, executionContext } from '../../../utils/access';
import { getEntitiesMapFromCache } from '../../../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../schema/stixMetaObject';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../schema/schema-relationsRef';
import { getParentTypes } from '../../../schema/schemaUtils';
import { STIX_EXT_MITRE, STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../types/stix-2-1-extensions';
import { isNotEmptyField } from '../../../database/utils';
import type { BasicStoreCommon } from '../../../types/store';
import { EditOperation } from '../../../generated/graphql';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  INPUT_ASSIGNEE,
  INPUT_CREATED_BY,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_PARTICIPANT
} from '../../../schema/general';
import { createdBy, objectLabel, objectMarking } from '../../../schema/stixRefRelationship';
import { ENTITY_TYPE_INDICATOR } from '../../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../organization/organization-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../../case/case-types';

const attributePathMapping: any = {
  [INPUT_MARKINGS]: {
    [ABSTRACT_STIX_CORE_OBJECT]: `/${objectMarking.stixName}`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/${objectMarking.stixName}`,
  },
  [INPUT_LABELS]: {
    [ABSTRACT_STIX_CORE_OBJECT]: `/extensions/${STIX_EXT_OCTI}/labels_ids`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/extensions/${STIX_EXT_OCTI}/labels_ids`,
  },
  [INPUT_CREATED_BY]: {
    [ABSTRACT_STIX_CORE_OBJECT]: `/${createdBy.stixName}`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/${createdBy.stixName}`,
  },
  [INPUT_ASSIGNEE]: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: `/extensions/${STIX_EXT_OCTI}/assignee_ids`,
  },
  [INPUT_PARTICIPANT]: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: `/extensions/${STIX_EXT_OCTI}/participant_ids`,
  },
  confidence: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: '/confidence',
    [ABSTRACT_STIX_RELATIONSHIP]: '/confidence',
  },
  x_opencti_score: {
    [ENTITY_TYPE_INDICATOR]: `/extensions/${STIX_EXT_OCTI}/score`,
    [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI_SCO}/score`,
    [ENTITY_TYPE_IDENTITY_ORGANIZATION]: `/extensions/${STIX_EXT_OCTI}/score`,
  },
  x_opencti_detection: {
    [ENTITY_TYPE_INDICATOR]: `/extensions/${STIX_EXT_OCTI}/detection`,
  },
  x_opencti_workflow_id: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: `/extensions/${STIX_EXT_OCTI}/workflow_id`,
    [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI}/workflow_id`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/extensions/${STIX_EXT_OCTI}/workflow_id`,
  },
  severity: {
    [ENTITY_TYPE_CONTAINER_CASE]: '/severity',
  },
  priority: {
    [ENTITY_TYPE_CONTAINER_CASE]: '/priority',
  },
  indicator_types: {
    [ENTITY_TYPE_INDICATOR]: '/indicator_types',
  },
  [INPUT_KILLCHAIN]: {
    [ENTITY_TYPE_INDICATOR]: '/kill_chain_phases',
  },
  x_mitre_platforms: {
    [ENTITY_TYPE_INDICATOR]: `/extensions/${STIX_EXT_MITRE}/platforms`
  },
};

interface UpdateValueConfiguration {
  label: string
  value: string
  patch_value: string
}

interface PatchConfiguration {
  actions: { op: 'remove', attribute: string, value: UpdateValueConfiguration[] }[]
  all: boolean
}
const PLAYBOOK_PATCH_KNOWLEDGE_COMPONENT_SCHEMA: JSONSchemaType<PatchConfiguration> = {
  type: 'object',
  properties: {
    actions: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          op: { type: 'string', enum: ['remove'] },
          attribute: { type: 'string' },
          value: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                label: { type: 'string' },
                value: { type: 'string' },
                patch_value: { type: 'string' }
              },
              required: ['label', 'value', 'patch_value'],
            }
          },
        },
        required: ['op', 'attribute', 'value'],
      }
    },
    all: { type: 'boolean', $ref: 'Manipulate all elements included in the bundle', default: false },
  },
  required: ['actions'],
};

export const PLAYBOOK_PATCH_KNOWLEDGE_COMPONENT: PlaybookComponent<PatchConfiguration> = {
  id: 'PLAYBOOK_PATCH_KNOWLEDGE_COMPONENT',
  name: 'Patch knowledge',
  description: 'Patch STIX',
  icon: 'edit',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
  configuration_schema: PLAYBOOK_PATCH_KNOWLEDGE_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_PATCH_KNOWLEDGE_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const cacheIds = await getEntitiesMapFromCache(context, AUTOMATION_MANAGER_USER, ENTITY_TYPE_MARKING_DEFINITION);
    const { actions, all } = playbookNode.configuration;
    // Compute if the attribute is defined as multiple in schema definition
    const isAttributeMultiple = (entityType:string, attribute: string) => {
      const baseAttribute = schemaAttributesDefinition.getAttribute(entityType, attribute);
      if (baseAttribute) return baseAttribute.multiple;
      const relationRef = schemaRelationsRefDefinition.getRelationRef(entityType, attribute);
      if (relationRef) return relationRef.multiple;
      return undefined;
    };
    const getAttributeType = (entityType:string, attribute: string) => {
      const baseAttribute = schemaAttributesDefinition.getAttribute(entityType, attribute);
      return baseAttribute?.type ?? 'string';
    };
    // Compute the access path for the attribute in the static matrix
    const computeAttributePath = (entityType:string, attribute: string) => {
      if (attributePathMapping[attribute]) {
        if (attributePathMapping[attribute][entityType]) {
          return attributePathMapping[attribute][entityType];
        }
        const key = Object.keys(attributePathMapping[attribute]).filter((o) => getParentTypes(entityType).includes(o)).at(0);
        if (key) {
          return attributePathMapping[attribute][key];
        }
      }
      return undefined;
    };
    const convertValue = (attributeType: string, value: any) => {
      if (attributeType === 'numeric') return Number(value);
      if (attributeType === 'boolean') return value.toLowerCase() === 'true';
      return value;
    };
    const patchOperations = [];
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const element = bundle.objects[index];
      if (all || element.id === dataInstanceId) {
        const { type } = element.extensions[STIX_EXT_OCTI];
        const elementOperations = actions
          .map((action) => {
            const attrPath = computeAttributePath(type, action.attribute);
            const multiple = isAttributeMultiple(type, action.attribute);
            const attributeType = getAttributeType(type, action.attribute);
            return ({ action, multiple, attributeType, attrPath, path: `/objects/${index}${attrPath}` });
          })
          // Unrecognized attributes must be filtered
          .filter(({ attrPath, multiple }) => isNotEmptyField(multiple) && isNotEmptyField(attrPath))
          // Map actions to data patches
          .map(({ action, path, multiple, attributeType }) => {
            if (multiple) {
              const currentValues = jsonpatch.getValueByPointer(bundle, path) ?? [];
              const actionValues = action.value.map((o) => {
                // If value is an id, must be converted to standard_id has we work on stix bundle
                if (cacheIds.has(o.value)) return (cacheIds.get(o.value) as BasicStoreCommon).standard_id;
                // Else, just return the value
                return convertValue(attributeType, o.value);
              });
              if (action.op === EditOperation.Remove) {
                return { op: EditOperation.Replace, path, value: currentValues.filter((c: any) => !actionValues.includes(c)) };
              }
            }
            const currentValue = R.head(action.value)?.patch_value;
            return { op: action.op, path, value: convertValue(attributeType, currentValue), action_attribute: action.attribute };
          });
        // Enlist operations to execute
        if (elementOperations.length > 0) {
          const operationObject = [{ key: INPUT_LABELS, value: ['65de1c32-b99d-455b-9824-2f411d1baf7a'], operation: 'remove' }];
          element.extensions[STIX_EXT_OCTI].opencti_operation = 'upsert_patch';
          element.extensions[STIX_EXT_OCTI].opencti_field_patch = operationObject;
          patchOperations.push(...elementOperations);
        }
      }
    }
    // Apply operations if needed
    if (patchOperations.length > 0) {
      const patchedBundle = jsonpatch.applyPatch(structuredClone(bundle), patchOperations).newDocument;
      const diff = jsonpatch.compare(bundle, patchedBundle);
      if (isNotEmptyField(diff)) {
        return { output_port: 'out', bundle: patchedBundle };
      }
    }
    return { output_port: 'unmodified', bundle };
  }

};
