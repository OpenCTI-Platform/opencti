import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { RELATION_OBJECT } from '../../schema/stixMetaRelationship';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';

const id = 'observe_sighting';
const name = 'Sighting observable';
const description =
  'If **observed-data A (created-by Organization X)** have `object` **observable B** and **indicator C** ' +
  'is `based-on` **observable B**, and `revoked` = **false** and `x_opencti_detection` = **false**' +
  'then **indicator C** is `sighted` in **organization X**.';

// For rescan
const scan = {
  types: [RELATION_OBJECT],
  fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA],
  toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE],
};

// For live
const scopes = [
  {
    // eslint-disable-next-line prettier/prettier
    filters: {
      types: [RELATION_OBJECT],
      fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA],
      toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE],
    },
    attributes: [],
  },
  {
    // eslint-disable-next-line prettier/prettier
    filters: {
      types: [RELATION_BASED_ON],
      fromTypes: [ENTITY_TYPE_INDICATOR],
      toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE],
    },
    attributes: [],
  },
  {
    filters: { types: [ENTITY_TYPE_INDICATOR] },
    attributes: [
      { name: 'revoked', dependency: true },
      { name: 'x_opencti_detection', dependency: true },
    ],
  },
  {
    filters: { types: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA] },
    attributes: [
      { name: 'created_by_ref', dependency: true },
      { name: 'first_observed' },
      { name: 'last_observed' },
      { name: 'number_observed' },
      { name: 'confidence' },
      { name: 'object_marking_refs' },
    ],
  },
];

const definition = { id, name, description, scan, scopes };
export default definition;
