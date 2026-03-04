import * as R from 'ramda';
import type { JSONSchemaType } from 'ajv';
import { type PlaybookComponent } from '../playbook-types';
import { AUTOMATION_MANAGER_USER, executionContext } from '../../../utils/access';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, ENTITY_TYPE_THREAT_ACTOR } from '../../../schema/general';
import type { StoreCommon, StoreRelation } from '../../../types/store';
import { generateInternalId, generateStandardId, idGenFromData } from '../../../schema/identifier';
import { now, observableValue } from '../../../utils/format';
import type { StixContainer } from '../../../types/stix-2-1-sdo';
import { getParentTypes } from '../../../schema/schemaUtils';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
  isStixDomainObjectContainer,
} from '../../../schema/stixDomainObject';
import type { StixCoreObject, StixCyberObject, StixObject } from '../../../types/stix-2-1-common';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../types/stix-2-1-extensions';
import { fullRelationsList } from '../../../database/middleware-loader';
import { isEmptyField, isNotEmptyField, READ_RELATIONSHIPS_INDICES } from '../../../database/utils';
import { stixLoadByIds } from '../../../database/middleware';
import { isStixCyberObservable } from '../../../schema/stixCyberObservable';
import { createStixPattern } from '../../../python/pythonBridge';
import { generateKeyValueForIndicator } from '../../../domain/stixCyberObservable';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../../../schema/stixCoreRelationship';
import type { StixRelation } from '../../../types/stix-2-1-sro';
import { STIX_PATTERN_TYPE } from '../../../utils/syntax';
import { ENTITY_TYPE_INDICATOR, type StixIndicator } from '../../indicator/indicator-types';
import { schemaTypesDefinition } from '../../../schema/schema-types';
import { extractBundleBaseElement } from '../playbook-utils';
import { convertStoreToStix_2_1 } from '../../../database/stix-2-1-converter';
import { pushAll } from '../../../utils/arrayUtil';

interface CreateIndicatorConfiguration {
  all: boolean;
  wrap_in_container: boolean;
  types: string[];
}
const PLAYBOOK_CREATE_INDICATOR_COMPONENT_SCHEMA: JSONSchemaType<CreateIndicatorConfiguration> = {
  type: 'object',
  properties: {
    types: {
      type: 'array',
      default: [],
      $ref: 'Types',
      items: { type: 'string', oneOf: [] },
    },
    all: { type: 'boolean', $ref: 'Create indicators from all observables in the bundle', default: false },
    wrap_in_container: { type: 'boolean', $ref: 'If main entity is a container, wrap indicators in container', default: false },
  },
  required: [],
};
export const PLAYBOOK_CREATE_INDICATOR_COMPONENT: PlaybookComponent<CreateIndicatorConfiguration> = {
  id: 'PLAYBOOK_CREATE_INDICATOR_COMPONENT',
  name: 'Promote observable to indicator',
  description: 'Create an indicator based on an observable',
  icon: 'indicator',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
  configuration_schema: PLAYBOOK_CREATE_INDICATOR_COMPONENT_SCHEMA,
  schema: async () => {
    const types = schemaTypesDefinition.get(ABSTRACT_STIX_CYBER_OBSERVABLE);
    const elements = types.map((t) => ({ const: t, title: t }))
      .sort((a, b) => (a.title.toLowerCase() > b.title.toLowerCase() ? 1 : -1));
    const schemaElement = { properties: { types: { items: { oneOf: elements } } } };
    return R.mergeDeepRight<JSONSchemaType<CreateIndicatorConfiguration>, any>(PLAYBOOK_CREATE_INDICATOR_COMPONENT_SCHEMA, schemaElement);
  },
  executor: async ({ playbookNode, dataInstanceId, bundle }) => {
    const { all, wrap_in_container, types } = playbookNode.configuration;
    const context = executionContext('playbook_components');
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const observables = [baseData];
    if (all) {
      pushAll(observables, bundle.objects);
    }
    const { type: baseDataType, id } = baseData.extensions[STIX_EXT_OCTI];
    const isBaseDataAContainer = isStixDomainObjectContainer(baseDataType);
    const objectsToPush: StixObject[] = [];
    for (let index = 0; index < observables.length; index += 1) {
      const observable = observables[index] as StixCyberObject;
      let { type } = observable.extensions[STIX_EXT_OCTI];
      if (isStixCyberObservable(type) && (isEmptyField(types) || types.includes(type))) {
        const indicatorName = observableValue({ ...observable, entity_type: type });
        const { key, value } = generateKeyValueForIndicator(type, indicatorName, observable);
        if (key.includes('Artifact')) {
          type = 'StixFile';
        }
        const pattern = await createStixPattern(context, AUTOMATION_MANAGER_USER, key, value);
        const score = observable.x_opencti_score ?? observable.extensions[STIX_EXT_OCTI_SCO]?.score;
        const { granted_refs } = observable.extensions[STIX_EXT_OCTI];
        if (pattern) {
          const indicatorData = {
            name: indicatorName,
            x_opencti_main_observable_type: type,
            x_opencti_score: score,
            pattern,
            pattern_type: STIX_PATTERN_TYPE,
            extensions: {
              [STIX_EXT_OCTI]: {
                extension_type: 'property-extension',
                type: ENTITY_TYPE_INDICATOR,
                main_observable_type: type,
                score,
              },
            },
          };
          const indicatorStandardId = generateStandardId(ENTITY_TYPE_INDICATOR, indicatorData);
          const storeIndicator = {
            internal_id: generateInternalId(),
            standard_id: indicatorStandardId,
            entity_type: ENTITY_TYPE_INDICATOR,
            parent_types: getParentTypes(ENTITY_TYPE_INDICATOR),
            ...indicatorData,
          } as StoreCommon;
          const indicator = convertStoreToStix_2_1(storeIndicator) as StixIndicator;
          if (observable.object_marking_refs) {
            indicator.object_marking_refs = observable.object_marking_refs;
          }
          if (observable.extensions[STIX_EXT_OCTI_SCO]?.labels) {
            indicator.labels = observable.extensions[STIX_EXT_OCTI_SCO].labels;
          }
          if (observable.extensions[STIX_EXT_OCTI_SCO]?.created_by_ref) {
            indicator.created_by_ref = observable.extensions[STIX_EXT_OCTI_SCO].created_by_ref;
          }
          if (observable.extensions[STIX_EXT_OCTI_SCO]?.external_references) {
            indicator.external_references = observable.extensions[STIX_EXT_OCTI_SCO].external_references;
          }
          if (granted_refs) {
            indicator.extensions[STIX_EXT_OCTI].granted_refs = granted_refs;
          }
          objectsToPush.push(indicator);
          if (wrap_in_container && isBaseDataAContainer) {
            (baseData as StixContainer).object_refs.push(indicator.id);
          }
          const relationBaseData = {
            source_ref: indicator.id,
            target_ref: observable.id,
            relationship_type: RELATION_BASED_ON,
          };
          const relationStandardId = idGenFromData('relationship', relationBaseData);
          const relationship = {
            id: relationStandardId,
            type: 'relationship',
            ...relationBaseData,
            object_marking_refs: observable.object_marking_refs ?? [],
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

          // Resolve relationships in the bundle
          const stixRelationshipsInBundle = bundle.objects.filter((r) => r.type === 'relationship') as StixRelation[];
          const stixRelationships = stixRelationshipsInBundle.filter((r) => r.relationship_type === 'related-to'
            && r.source_ref === baseData.id
            && (
              r.target_ref.startsWith('threat-actor')
              || r.target_ref.startsWith('intrusion-set')
              || r.target_ref.startsWith('campaign')
              || r.target_ref.startsWith('malware')
              || r.target_ref.startsWith('incident')
              || r.target_ref.startsWith('tool')
              || r.target_ref.startsWith('attack-pattern')
            ));
          for (let indexStixRelationships = 0; indexStixRelationships < stixRelationships.length; indexStixRelationships += 1) {
            const stixRelationship = stixRelationships[indexStixRelationships] as StixRelation;
            const relationIndicatesBaseData = {
              source_ref: indicator.id,
              target_ref: stixRelationship.target_ref,
              relationship_type: RELATION_INDICATES,
            };
            const relationIndicatesStandardId = idGenFromData('relationship', relationIndicatesBaseData);
            const relationshipIndicates = {
              id: relationIndicatesStandardId,
              type: 'relationship',
              ...relationIndicatesBaseData,
              object_marking_refs: observable.object_marking_refs ?? [],
              created: now(),
              modified: now(),
              extensions: {
                [STIX_EXT_OCTI]: {
                  extension_type: 'property-extension',
                  type: RELATION_INDICATES,
                },
              },
            } as StixRelation;
            if (granted_refs) {
              relationshipIndicates.extensions[STIX_EXT_OCTI].granted_refs = granted_refs;
            }
            objectsToPush.push(relationshipIndicates);
          }
          // Resolve relationships in database
          if (isNotEmptyField(id)) {
            const relationsOfObservables = await fullRelationsList(
              context,
              AUTOMATION_MANAGER_USER,
              ABSTRACT_STIX_CORE_RELATIONSHIP,
              {
                fromOrToId: id,
                toTypes: [
                  ENTITY_TYPE_THREAT_ACTOR,
                  ENTITY_TYPE_INTRUSION_SET,
                  ENTITY_TYPE_CAMPAIGN,
                  ENTITY_TYPE_MALWARE,
                  ENTITY_TYPE_INCIDENT,
                  ENTITY_TYPE_TOOL,
                  ENTITY_TYPE_ATTACK_PATTERN,
                ],
                baseData: true,
                indices: READ_RELATIONSHIPS_INDICES,
              },
            ) as StoreRelation[];
            const idsToResolve = R.uniq(relationsOfObservables.map((r) => r.toId));
            const elements = await stixLoadByIds(context, AUTOMATION_MANAGER_USER, idsToResolve);
            for (let indexElements = 0; indexElements < elements.length; indexElements += 1) {
              const element = elements[indexElements] as StixCoreObject;
              const relationIndicatesBaseData = {
                source_ref: indicator.id,
                target_ref: element.id,
                relationship_type: RELATION_INDICATES,
              };
              const relationIndicatesStandardId = idGenFromData('relationship', relationIndicatesBaseData);
              const relationshipIndicates = {
                id: relationIndicatesStandardId,
                type: 'relationship',
                ...relationIndicatesBaseData,
                object_marking_refs: observable.object_marking_refs ?? [],
                created: now(),
                modified: now(),
                extensions: {
                  [STIX_EXT_OCTI]: {
                    extension_type: 'property-extension',
                    type: RELATION_INDICATES,
                  },
                },
              } as StixRelation;
              if (granted_refs) {
                relationshipIndicates.extensions[STIX_EXT_OCTI].granted_refs = granted_refs;
              }
              objectsToPush.push(relationshipIndicates);
            }
          }
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
