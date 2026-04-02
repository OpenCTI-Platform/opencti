import * as R from 'ramda';
import type { JSONSchemaType } from 'ajv';
import { playbookBundleElementsToApply, type PlaybookBundleElementsToApply, type PlaybookComponent } from '../playbook-types';
import type { StoreCommon } from '../../../types/store';
import { generateInternalId, generateStandardId, idGenFromData } from '../../../schema/identifier';
import { now } from '../../../utils/format';
import type { StixContainer } from '../../../types/stix-2-1-sdo';
import { getParentTypes } from '../../../schema/schemaUtils';
import { isStixDomainObjectContainer } from '../../../schema/stixDomainObject';
import type { StixCyberObject, StixObject } from '../../../types/stix-2-1-common';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../types/stix-2-1-extensions';
import { RELATION_BASED_ON } from '../../../schema/stixCoreRelationship';
import type { StixRelation } from '../../../types/stix-2-1-sro';
import { extractValidObservablesFromIndicatorPattern } from '../../../utils/syntax';
import { type StixIndicator } from '../../indicator/indicator-types';
import { extractBundleBaseElement, isBundleElementInScope } from '../playbook-utils';
import { convertStoreToStix_2_1 } from '../../../database/stix-2-1-converter';
import { pushAll } from '../../../utils/arrayUtil';

interface CreateObservableConfiguration {
  applyToElements: PlaybookBundleElementsToApply;
  wrap_in_container: boolean;
}
const PLAYBOOK_CREATE_OBSERVABLE_COMPONENT_SCHEMA: JSONSchemaType<CreateObservableConfiguration> = {
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
    wrap_in_container: { type: 'boolean', $ref: 'If main entity is a container, wrap observables in container', default: false },
  },
  required: ['applyToElements'],
};
export const PLAYBOOK_CREATE_OBSERVABLE_COMPONENT: PlaybookComponent<CreateObservableConfiguration> = {
  id: 'PLAYBOOK_CREATE_OBSERVABLE_COMPONENT',
  name: 'Extract observables from indicator',
  description: 'Create observables based on an indicator',
  icon: 'observable',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
  configuration_schema: PLAYBOOK_CREATE_OBSERVABLE_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_CREATE_OBSERVABLE_COMPONENT_SCHEMA,
  executor: async ({ playbookNode, dataInstanceId, bundle }) => {
    const { applyToElements, wrap_in_container } = playbookNode.configuration;
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    // const indicators = [baseData];
    // if (all) {
    //   pushAll(indicators, bundle.objects.filter((object) => object.id !== dataInstanceId));
    // }

    const elementsToApply = bundle.objects.filter((object) => isBundleElementInScope(object, applyToElements, dataInstanceId));
    const { type: baseDataType } = baseData.extensions[STIX_EXT_OCTI];
    const isBaseDataAContainer = isStixDomainObjectContainer(baseDataType);
    const objectsToPush: StixObject[] = [];
    for (let indexIndicator = 0; indexIndicator < elementsToApply.length; indexIndicator += 1) {
      const indicator = elementsToApply[indexIndicator] as StixIndicator;
      if (indicator.type === 'indicator') {
        const observables = extractValidObservablesFromIndicatorPattern(indicator.pattern);
        for (let indexObservable = 0; indexObservable < observables.length; indexObservable += 1) {
          const observable = observables[indexObservable];
          const description = indicator.description ?? `Simple observable of indicator {${indicator.name || indicator.pattern}}`;
          const { score, granted_refs } = indicator.extensions[STIX_EXT_OCTI];
          const observableData = {
            ...R.dissoc('type', observable),
            x_opencti_score: score,
            x_opencti_description: description,
            extensions: {
              [STIX_EXT_OCTI]: {
                extension_type: 'property-extension',
                type: observable.type,
              },
              [STIX_EXT_OCTI_SCO]: {
                extension_type: 'property-extension',
                score,
                description,
              },
            },
          };
          const observableStandardId = generateStandardId(observable.type, observableData);
          const storeObservable = {
            internal_id: generateInternalId(),
            standard_id: observableStandardId,
            entity_type: observable.type,
            parent_types: getParentTypes(observable.type),
            ...observableData,
          } as StoreCommon;
          const stixObservable = convertStoreToStix_2_1(storeObservable) as StixCyberObject;
          if (indicator.object_marking_refs) {
            stixObservable.object_marking_refs = indicator.object_marking_refs;
          }
          if (indicator.created_by_ref && stixObservable.extensions[STIX_EXT_OCTI_SCO]) {
            stixObservable.extensions[STIX_EXT_OCTI_SCO].created_by_ref = indicator.created_by_ref;
          }
          if (indicator.labels && stixObservable.extensions[STIX_EXT_OCTI_SCO]) {
            stixObservable.extensions[STIX_EXT_OCTI_SCO].labels = indicator.labels;
          }
          if (indicator.external_references && stixObservable.extensions[STIX_EXT_OCTI_SCO]) {
            stixObservable.extensions[STIX_EXT_OCTI_SCO].external_references = indicator.external_references;
          }
          if (granted_refs) {
            stixObservable.extensions[STIX_EXT_OCTI].granted_refs = granted_refs;
          }
          objectsToPush.push(stixObservable);
          if (wrap_in_container && isBaseDataAContainer) {
            (baseData as StixContainer).object_refs.push(stixObservable.id);
          }
          const relationBaseData = {
            source_ref: indicator.id,
            target_ref: stixObservable.id,
            relationship_type: RELATION_BASED_ON,
          };
          const relationStandardId = idGenFromData('relationship', relationBaseData);
          const relationship = {
            id: relationStandardId,
            type: 'relationship',
            ...relationBaseData,
            object_marking_refs: indicator.object_marking_refs ?? [],
            created: now(),
            modified: now(),
            extensions: {
              [STIX_EXT_OCTI]: {
                extension_type: 'property-extension',
                type: RELATION_BASED_ON,
              },
            },
          } as StixRelation;
          if (granted_refs) {
            relationship.extensions[STIX_EXT_OCTI].granted_refs = granted_refs;
          }
          objectsToPush.push(relationship);
          if (wrap_in_container && isBaseDataAContainer) {
            (baseData as StixContainer).object_refs.push(relationship.id);
          }
        }
      }
    }
    if (objectsToPush.length > 0) {
      pushAll(bundle.objects, objectsToPush);
      return { output_port: 'out', bundle: { ...bundle, objects: bundle.objects.map((n) => (n.id === baseData.id ? baseData : n)) } };
    }
    return { output_port: 'unmodified', bundle };
  },
};
