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
    filters: { types: [RELATION_OBJECT], fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA], toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE] },
    attributes: ['first_seen', 'last_seen'],
  },
  {
    // eslint-disable-next-line prettier/prettier
    filters: { types: [RELATION_BASED_ON], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE] },
    attributes: ['first_seen', 'last_seen'],
  },
  {
    filters: { types: [ENTITY_TYPE_INDICATOR] },
    attributes: ['revoked', 'x_opencti_detection'],
  },
  {
    filters: { types: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA] },
    // eslint-disable-next-line prettier/prettier
    attributes: ['created_by_ref', 'first_observed', 'last_observed', 'number_observed', 'confidence', 'object_marking_refs'],
  },
];

const definition = { id, name, description, scan, scopes };
export default definition;
