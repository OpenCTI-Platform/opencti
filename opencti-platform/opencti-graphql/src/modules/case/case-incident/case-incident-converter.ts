import { buildStixDomain } from '../../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { INPUT_OBJECTS } from '../../../schema/general';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT, type Stix2CaseIncident, type StixCaseIncident, type StoreEntityCaseIncident } from './case-incident-types';
import { assertType, cleanObject } from '../../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../../database/stix-2-0-converter';
import { CF_COMMENT_KEY, CF_SCORE_KEY } from '../../customField/custom-field-domain';
import type { StoreEntity } from '../../../types/store';

export const convertCaseIncidentToStix_2_1 = (instance: StoreEntity): StixCaseIncident => {
  const caseIncidentInstance = instance as unknown as StoreEntityCaseIncident;
  const caseIncident = buildStixDomain(instance);

  // FIXME hack for POC
  const customFields: Record<string, any> = {};
  if (instance.custom_field_values) {
    const customScore = instance.custom_field_values.find((c) => c.field_name === CF_SCORE_KEY)?.int_value;
    if (customScore) {
      customFields['x_opencti_cf_score'] = customScore;
    }
    const customComment = instance.custom_field_values.find((c) => c.field_name === CF_COMMENT_KEY)?.string_value;
    if (customComment) {
      customFields['x_opencti_cf_comment'] = customComment;
    }
  }
  return {
    ...caseIncident,
    name: instance.name,
    description: instance.description,
    content: instance.content,
    content_mapping: instance.content_mapping,
    severity: instance.severity,
    priority: caseIncidentInstance.priority,
    response_types: caseIncidentInstance.response_types,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...caseIncident.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
        ...customFields,
      }),
    },
  };
};

export const convertCaseIncidentToStix_2_0 = (instance: StoreEntityCaseIncident): Stix2CaseIncident => {
  assertType(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, instance.entity_type);
  const caseIncident = buildStixDomain2(instance);
  return {
    ...caseIncident,
    name: instance.name,
    description: instance.description,
    severity: instance.severity,
    priority: instance.priority,
    response_types: instance.response_types,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
  };
};
