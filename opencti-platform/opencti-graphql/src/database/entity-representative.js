import moment from 'moment';
import { isEmptyField, isNotEmptyField } from './utils';
import { isStixRelationship } from '../schema/stixRelationship';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_STATUS } from '../schema/internalObject';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { observableValue } from '../utils/format';

export const extractRepresentativeDescription = (entityData) => {
  let secondValue;

  // BasicStoreRelation | BasicStoreEntity
  if (isNotEmptyField(entityData.description)) {
    secondValue = entityData.description;
    // BasicStoreCyberObservable
  } else if (isNotEmptyField(entityData.x_opencti_description)) {
    secondValue = entityData.x_opencti_description;
    // BasicStoreEntity | BasicStoreCyberObservable
  } else if (isNotEmptyField(entityData.content)) {
    secondValue = entityData.content;
  }

  return secondValue;
};

// -- RELATIONSHIP --

const extractRelationshipRepresentativeName = (relationshipData) => {
  return `${relationshipData.fromName} ➡️ ${relationshipData.toName}`;
};

const extractRelationshipRepresentative = (relationshipData) => {
  return {
    main: extractRelationshipRepresentativeName(relationshipData),
    secondary: extractRepresentativeDescription(relationshipData)
  };
};

// -- ENTITY --

// TODO migrate to extractStixRepresentative from convertStoreToStix
export const extractEntityRepresentativeName = (entityData) => {
  let mainValue;
  if (isStixCyberObservable(entityData.entity_type)) {
    mainValue = observableValue(entityData);
  } else if (entityData.entity_type === ENTITY_TYPE_STATUS && entityData.name && entityData.type) {
    mainValue = `${entityData.type} - ${entityData.name}`;
  } else if (isNotEmptyField(entityData.template) && isNotEmptyField(entityData.template.name)) {
    mainValue = entityData.template.name;
  } else if (isNotEmptyField(entityData.definition)) {
    mainValue = entityData.definition;
  } else if (isNotEmptyField(entityData.value)) {
    mainValue = entityData.value;
  } else if (isNotEmptyField(entityData.attribute_abstract)) {
    mainValue = entityData.attribute_abstract;
  } else if (isNotEmptyField(entityData.opinion)) {
    mainValue = entityData.opinion;
  } else if (isNotEmptyField(entityData.observable_value)) {
    mainValue = entityData.observable_value;
  } else if (isNotEmptyField(entityData.indicator_pattern)) {
    mainValue = entityData.indicator_pattern;
  } else if (isNotEmptyField(entityData.relationship_type)) {
    mainValue = extractRelationshipRepresentativeName(entityData);
  } else if (isNotEmptyField(entityData.source_name)) {
    mainValue = `${entityData.source_name}${entityData.external_id ? ` (${entityData.external_id})` : ''}`;
  } else if (isNotEmptyField(entityData.phase_name)) {
    mainValue = entityData.phase_name;
  } else if (isNotEmptyField(entityData.first_observed) && isNotEmptyField(entityData.last_observed)) {
    const from = moment(entityData.first_observed)
      .utc()
      .toISOString();
    const to = moment(entityData.last_observed)
      .utc()
      .toISOString();
    mainValue = `${from} - ${to}`;
  } else if (entityData.entity_type === ENTITY_TYPE_CAPABILITY) {
    return entityData.description;
  } else if (isNotEmptyField(entityData.result_name)) { // MALWARE-ANALYSES
    mainValue = entityData.result_name;
  } else if (isNotEmptyField(entityData.name)) {
    mainValue = entityData.name;
    if (isNotEmptyField(entityData.x_mitre_id)) { // Attack Pattern
      mainValue = `[${entityData.x_mitre_id}] ${mainValue}`;
    }
  } else if (isNotEmptyField(entityData.description)) {
    mainValue = entityData.description;
  }
  // If no representative value found, return the standard id
  if (isEmptyField(mainValue)) {
    return 'Unknown';
  }

  return String(mainValue);
};

const extractEntityRepresentative = (entityData) => {
  return {
    main: extractEntityRepresentativeName(entityData),
    secondary: extractRepresentativeDescription(entityData)
  };
};

// -- ENTITY | RELATIONSHIP

export const extractRepresentative = (entityData) => {
  // the representative can already be given (happens when the internals set it to "Restricted")
  if (entityData.representative) {
    return entityData.representative;
  }
  // otherwise we find extract it depending on the entity type
  if (isStixRelationship(entityData.entity_type)) {
    return extractRelationshipRepresentative(entityData);
  }

  return extractEntityRepresentative(entityData);
};
