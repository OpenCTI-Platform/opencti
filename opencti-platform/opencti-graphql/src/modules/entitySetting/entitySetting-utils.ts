import { head } from 'ramda';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ENTITY_TYPE_CONTAINER,
  INPUT_AUTHORIZED_MEMBERS,
  INPUT_GRANTED_REFS,
  INPUT_MARKINGS,
} from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OPINION, isStixDomainObject, isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import { UnsupportedError } from '../../config/errors';
import type { AttributeConfiguration, BasicStoreEntityEntitySetting } from './entitySetting-types';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { getEntitiesListFromCache } from '../../database/cache';
import { MEMBER_ACCESS_CREATOR, SYSTEM_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { ENTITY_TYPE_CONTAINER_TASK } from '../task/task-types';
import { isBooleanAttribute, isNumericAttribute, schemaAttributesDefinition } from '../../schema/schema-attributes';
import { isEmptyField } from '../../database/utils';
import type { MandatoryType } from '../../schema/attribute-definition';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../schema/stixMetaObject';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../case/case-rfi/case-rfi-types';

export type typeAvailableSetting = boolean | string;

export interface EntitySettingSchemaAttribute {
  name: string;
  type: string;
  mandatory: boolean;
  mandatoryType: MandatoryType;
  multiple: boolean;
  editDefault: boolean;
  upsert: boolean;
  label?: string;
  defaultValues?: { id: string; name: string }[];
  scale?: string;
}

export const defaultEntitySetting: Record<string, typeAvailableSetting> = {
  platform_entity_files_ref: false,
  platform_hidden_type: false,
  enforce_reference: false,
  attributes_configuration: JSON.stringify([]),
  workflow_configuration: true,
};

export const defaultScale = JSON.stringify({
  local_config: {
    better_side: 'min',
    min: {
      value: 0,
      color: '#f44336',
      label: '6 - Truth Cannot be judged',
    },
    max: {
      value: 100,
      color: '#6e44ad',
      label: 'Out of Range',
    },
    ticks: [
      { value: 1, color: '#f57423', label: '5 - Improbable' },
      { value: 20, color: '#ff9800', label: '4 - Doubtful' },
      { value: 40, color: '#f8e71c', label: '3 - Possibly True' },
      { value: 60, color: '#92f81c', label: '2 - Probably True' },
      { value: 80, color: '#4caf50', label: '1 - Confirmed by other sources' },
    ],
  },
});

// Available settings works by override.
export const availableSettings: Record<string, Array<string>> = {
  [ABSTRACT_STIX_DOMAIN_OBJECT]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'enforce_reference', 'workflow_configuration'],
  [ABSTRACT_STIX_CORE_RELATIONSHIP]: ['attributes_configuration', 'enforce_reference', 'workflow_configuration'],
  [STIX_SIGHTING_RELATIONSHIP]: ['attributes_configuration', 'enforce_reference', 'platform_hidden_type', 'workflow_configuration'],
  [ABSTRACT_STIX_CYBER_OBSERVABLE]: ['platform_hidden_type'],
  [ENTITY_TYPE_EXTERNAL_REFERENCE]: ['platform_hidden_type'],
  // add templates for containers
  [ENTITY_TYPE_CONTAINER]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'enforce_reference', 'workflow_configuration', 'templates'],
  // enforce_reference not available on specific entities
  [ENTITY_TYPE_CONTAINER_NOTE]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'workflow_configuration'],
  [ENTITY_TYPE_CONTAINER_OPINION]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'workflow_configuration'],
  [ENTITY_TYPE_CONTAINER_CASE]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'workflow_configuration'],
  [ENTITY_TYPE_CONTAINER_TASK]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'workflow_configuration'],
  [ENTITY_TYPE_CONTAINER_CASE_RFI]: ['attributes_configuration', 'platform_entity_files_ref', 'platform_hidden_type', 'enforce_reference', 'workflow_configuration', 'templates', 'request_access_workflow'],
};

export const getAvailableSettings = (targetType: string) => {
  let settings;
  if (isStixDomainObject(targetType)) {
    const defaultSetting = isStixDomainObjectContainer(targetType)
      ? availableSettings[ENTITY_TYPE_CONTAINER]
      : availableSettings[ABSTRACT_STIX_DOMAIN_OBJECT];
    settings = availableSettings[targetType] ?? defaultSetting;
  } else if (isStixCyberObservable(targetType)) {
    settings = availableSettings[targetType] ?? availableSettings[ABSTRACT_STIX_CYBER_OBSERVABLE];
  } else {
    settings = availableSettings[targetType];
  }

  if (!settings) {
    throw UnsupportedError('This entity type is not support for entity settings', { target_type: targetType });
  }

  return settings;
};

// -- HELPERS --

export const getEntitySettingFromCache = async (context: AuthContext, type: string) => {
  const entitySettings = await getEntitiesListFromCache<BasicStoreEntityEntitySetting>(context, SYSTEM_USER, ENTITY_TYPE_ENTITY_SETTING);
  let entitySetting = entitySettings.find((es) => es.target_type === type);

  if (!entitySetting) {
    // Inheritance
    if (isStixCoreRelationship(type)) {
      entitySetting = entitySettings.find((es) => es.target_type === ABSTRACT_STIX_CORE_RELATIONSHIP);
    } else if (isStixCyberObservable(type)) {
      entitySetting = entitySettings.find((es) => es.target_type === ABSTRACT_STIX_CYBER_OBSERVABLE);
    }
  }

  return entitySetting;
};

export const getAttributesConfiguration = (entitySetting: BasicStoreEntityEntitySetting) => {
  if (entitySetting?.attributes_configuration) {
    return JSON.parse(entitySetting.attributes_configuration as string) as AttributeConfiguration[];
  }
  return null;
};

export const getDefaultValues = (attributeConfiguration: AttributeConfiguration, multiple: boolean): string[] | string | undefined => {
  if (attributeConfiguration.default_values) {
    if (multiple) {
      return attributeConfiguration.default_values;
    }
    return head(attributeConfiguration.default_values);
  }
  return undefined;
};

export const fillDefaultValues = (context: AuthContext, user: any, input: any, entitySetting: any) => {
  const filledValues = new Map();
  if (!context.user_inside_platform_organization) {
    filledValues.set(INPUT_GRANTED_REFS, user.organizations);
  }
  const attributesConfiguration = getAttributesConfiguration(entitySetting);
  if (attributesConfiguration) {
    attributesConfiguration.filter((attr) => attr.default_values)
      .forEach((attr) => {
        // Do not compute default value if we already have a value in the input.
        // Empty is a valid value (i.e. [] for arrays or "" for strings).
        if (input[attr.name] === undefined || input[attr.name] === null) {
          const attributeDef = schemaAttributesDefinition.getAttribute(entitySetting.target_type, attr.name);
          const refDef = schemaRelationsRefDefinition.getRelationRef(entitySetting.target_type, attr.name);
          let isMultiple = false;
          if (attributeDef) {
            isMultiple = attributeDef.multiple;
          } else if (refDef) {
            isMultiple = refDef.multiple;
          }
          const defaultValue = getDefaultValues(attr, isMultiple);

          const isNumeric = isNumericAttribute(attr.name);
          const isBoolean = isBooleanAttribute(attr.name);
          let parsedValue: any = defaultValue;
          if (isNumeric) parsedValue = Number(defaultValue);
          if (isBoolean) parsedValue = defaultValue === 'true';

          if (attr.name === INPUT_AUTHORIZED_MEMBERS && parsedValue) {
            const defaultAuthorizedMembers = (parsedValue as string[]).map((v) => JSON.parse(v));
            // Replace dynamic creator rule with the id of the user making the query.
            const creatorRule = defaultAuthorizedMembers.find((v) => v.id === MEMBER_ACCESS_CREATOR);
            if (creatorRule) {
              creatorRule.id = user.id;
            }
            filledValues.set(attr.name, defaultAuthorizedMembers);
          } else if (attr.name === INPUT_MARKINGS && parsedValue) {
            const defaultMarkings = user?.default_marking ?? [];
            const globalDefaultMarking = (defaultMarkings.find((entry: any) => entry.entity_type === 'GLOBAL')?.values ?? []).map((m: any) => m.id);
            if (!isEmptyField(globalDefaultMarking)) {
              filledValues.set(INPUT_MARKINGS, globalDefaultMarking);
            }
          } else {
            filledValues.set(attr.name, parsedValue);
          }
        }
      });
  }

  return { ...input, ...Object.fromEntries(filledValues) };
};
