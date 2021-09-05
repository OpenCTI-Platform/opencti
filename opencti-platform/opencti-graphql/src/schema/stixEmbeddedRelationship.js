import * as R from 'ramda';
import {
  EXTERNAL_META_TO_STIX_ATTRIBUTE,
  isSingleStixMetaRelationship,
  isStixMetaRelationship,
  STIX_ATTRIBUTE_TO_META_FIELD,
  STIX_META_RELATION_TO_OPENCTI_INPUT,
  isSingleStixMetaRelationshipInput,
} from './stixMetaRelationship';
import {
  EXTERNAL_CYBER_OBSERVABLE_TO_STIX_ATTRIBUTE,
  isSingleStixCyberObservableRelationship,
  isStixCyberObservableRelationship,
  STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD,
  STIX_CYBER_OBSERVABLE_RELATION_TO_OPENCTI_INPUT,
  isSingleStixCyberObservableRelationshipInput,
} from './stixCyberObservableRelationship';

export const EXTERNAL_EMBEDDED_TO_STIX_ATTRIBUTE = {
  ...EXTERNAL_META_TO_STIX_ATTRIBUTE,
  ...EXTERNAL_CYBER_OBSERVABLE_TO_STIX_ATTRIBUTE,
};
export const STIX_ATTRIBUTE_TO_EMBEDDED_REL = R.mergeAll(
  Object.keys(EXTERNAL_EMBEDDED_TO_STIX_ATTRIBUTE).map((k) => ({ [EXTERNAL_EMBEDDED_TO_STIX_ATTRIBUTE[k]]: k }))
);

export const STIX_ATTRIBUTE_TO_EMBEDDED_FIELD = {
  ...STIX_ATTRIBUTE_TO_META_FIELD,
  ...STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD,
};

export const STIX_EMBEDDED_RELATION_TO_OPENCTI_INPUT = {
  ...STIX_META_RELATION_TO_OPENCTI_INPUT,
  ...STIX_CYBER_OBSERVABLE_RELATION_TO_OPENCTI_INPUT,
};
export const OPENCTI_ATTRIBUTE_TO_EMBEDDED_REL = R.mergeAll(
  Object.keys(STIX_EMBEDDED_RELATION_TO_OPENCTI_INPUT).map((k) => ({ [STIX_META_RELATION_TO_OPENCTI_INPUT[k]]: k }))
);

export const isStixEmbeddedRelationship = (type) =>
  isStixMetaRelationship(type) || isStixCyberObservableRelationship(type);

export const isSingleStixEmbeddedRelationship = (type) =>
  isSingleStixMetaRelationship(type) || isSingleStixCyberObservableRelationship(type);

export const isSingleStixEmbeddedRelationshipInput = (input) =>
  isSingleStixMetaRelationshipInput(input) || isSingleStixCyberObservableRelationshipInput(input);
