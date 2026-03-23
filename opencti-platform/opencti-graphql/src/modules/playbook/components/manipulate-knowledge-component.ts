import * as R from 'ramda';
import type { JSONSchemaType } from 'ajv';
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
  INPUT_PARTICIPANT,
} from '../../../schema/general';
import type { BasicStoreCommon } from '../../../types/store';
import { STIX_EXT_MITRE, STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../types/stix-2-1-extensions';
import { getEntitiesMapFromCache } from '../../../database/cache';
import { createdBy, objectLabel, objectMarking } from '../../../schema/stixRefRelationship';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../schema/schema-relationsRef';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../schema/stixMetaObject';
import { ENTITY_TYPE_CONTAINER_CASE } from '../../case/case-types';
import { ENTITY_TYPE_INDICATOR } from '../../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../organization/organization-types';
import { ENTITY_TYPE_INCIDENT } from '../../../schema/stixDomainObject';
import { playbookBundleElementsToApply, type PlaybookBundleElementsToApply, type PlaybookComponent } from '../playbook-types';
import { AUTOMATION_MANAGER_USER, executionContext } from '../../../utils/access';
import { getParentTypes } from '../../../schema/schemaUtils';
import * as jsonpatch from 'fast-json-patch';
import { isNotEmptyField } from '../../../database/utils';
import { EditOperation } from '../../../generated/graphql';
import { applyOperationFieldPatch } from '../playbook-utils';
import { pushAll } from '../../../utils/arrayUtil';

const attributePathMapping: any = {
  [INPUT_MARKINGS]: {
    [ABSTRACT_STIX_CORE_OBJECT]: `/${objectMarking.stixName}`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/${objectMarking.stixName}`,
  },
  [INPUT_LABELS]: {
    [ABSTRACT_STIX_CORE_OBJECT]: `/${objectLabel.stixName}`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/${objectLabel.stixName}`,
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
    [ENTITY_TYPE_INCIDENT]: '/severity',
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
    [ENTITY_TYPE_INDICATOR]: `/extensions/${STIX_EXT_MITRE}/platforms`,
  },
};

export interface ManipulateConfiguration {
  actions: { op: 'add' | 'replace' | 'remove'; attribute: string; value: UpdateValueConfiguration[] }[];
  applyToElements: PlaybookBundleElementsToApply;
}
const PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT_SCHEMA: JSONSchemaType<ManipulateConfiguration> = {
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
    actions: {
      type: 'array',
      default: [],
      items: {
        type: 'object',
        properties: {
          op: { type: 'string', enum: ['add', 'replace', 'remove'] },
          attribute: { type: 'string' },
          value: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                label: { type: 'string' },
                value: { type: 'string' },
                patch_value: { type: 'string' },
              },
              required: ['label', 'value', 'patch_value'],
            },
          },
        },
        required: ['op', 'attribute', 'value'],
      },
    },
  },
  required: ['actions', 'applyToElements'],
};

interface UpdateValueConfiguration {
  label: string;
  value: string;
  patch_value: string;
}

export const PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT: PlaybookComponent<ManipulateConfiguration> = {
  id: 'PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT',
  name: 'Manipulate knowledge',
  description: 'Manipulate STIX data',
  icon: 'edit',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
  configuration_schema: PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const cacheIds = await getEntitiesMapFromCache(context, AUTOMATION_MANAGER_USER, ENTITY_TYPE_MARKING_DEFINITION);
    const { actions, applyToElements } = playbookNode.configuration;
    // Compute if the attribute is defined as multiple in schema definition
    const isAttributeMultiple = (entityType: string, attribute: string) => {
      const baseAttribute = schemaAttributesDefinition.getAttribute(entityType, attribute);
      if (baseAttribute) return baseAttribute.multiple;
      const relationRef = schemaRelationsRefDefinition.getRelationRef(entityType, attribute);
      if (relationRef) return relationRef.multiple;
      return undefined;
    };
    const getAttributeType = (entityType: string, attribute: string) => {
      const baseAttribute = schemaAttributesDefinition.getAttribute(entityType, attribute);
      return baseAttribute?.type ?? 'string';
    };
    // Compute the access path for the attribute in the static matrix
    const computeAttributePath = (entityType: string, attribute: string) => {
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

    const patchOperations: jsonpatch.Operation[] = [];
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const element = bundle.objects[index];
      const all = applyToElements === playbookBundleElementsToApply.allElements.value;
      const onlyMain = applyToElements === playbookBundleElementsToApply.onlyMain.value && element.id === dataInstanceId;
      const exceptMain = applyToElements === playbookBundleElementsToApply.allExceptMain.value && element.id !== dataInstanceId;
      if (all || onlyMain || exceptMain) {
        const { type, id } = element.extensions[STIX_EXT_OCTI];
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
              // the patch value can be the "label" instead of id (for ex: markings ids / labels ids)
              const actionPatchValues = action.value.map((o) => {
                // If value is an id, must be converted to standard_id has we work on stix bundle
                if (cacheIds.has(o.patch_value)) return (cacheIds.get(o.patch_value) as BasicStoreCommon).standard_id;
                // Else, just return the value
                return convertValue(attributeType, o.patch_value);
              });
              // the value is always the id
              const actionValues = action.value.map((o) => {
                // If value is an id, must be converted to standard_id has we work on stix bundle
                if (cacheIds.has(o.value)) return (cacheIds.get(o.value) as BasicStoreCommon).standard_id;
                // Else, just return the value
                return convertValue(attributeType, o.value);
              });
              if (action.op === EditOperation.Add) {
                return {
                  op: action.op,
                  attribute: action.attribute,
                  value: actionValues,
                  patchOperation: { op: EditOperation.Replace, path, value: R.uniq([...currentValues, ...actionPatchValues]) },
                };
              }
              if (action.op === EditOperation.Replace) {
                return {
                  op: action.op,
                  attribute: action.attribute,
                  value: actionValues,
                  patchOperation: { op: EditOperation.Replace, path, value: actionPatchValues },
                };
              }
              if (action.op === EditOperation.Remove) {
                return {
                  op: action.op,
                  attribute: action.attribute,
                  value: actionValues,
                  patchOperation: { op: EditOperation.Replace, path, value: currentValues.filter((c: any) => !actionPatchValues.includes(c)) },
                };
              }
            }
            const currentPatchValue = R.head(action.value)?.patch_value;
            const currentValue = R.head(action.value)?.value;
            return {
              op: action.op,
              attribute: action.attribute,
              value: currentValue,
              patchOperation: { op: action.op, path, value: convertValue(attributeType, currentPatchValue) },
            };
          });
        // Enlist operations to execute
        if (elementOperations.length > 0) {
          const operationObject = elementOperations.map((op) => {
            return { key: op.attribute, value: Array.isArray(op.value) ? op.value : [op.value], operation: op.op };
          });
          if (id) {
            applyOperationFieldPatch(element, operationObject);
          }
          pushAll(patchOperations, elementOperations.map((e) => e.patchOperation));
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
  },
};
