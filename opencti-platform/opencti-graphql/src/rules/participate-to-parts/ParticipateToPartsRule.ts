import { RELATION_PART_OF } from '../../schema/stixCoreRelationship';
import def from './ParticipateToPartsDefinition';
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../modules/organization/organization-types';

const ParticipateToPartsRule = buildRelationToRelationRule(def, {
  leftType: RELATION_PARTICIPATE_TO,
  rightType: RELATION_PART_OF,
  rightTypesTo: [ENTITY_TYPE_IDENTITY_ORGANIZATION],
  creationType: RELATION_PARTICIPATE_TO,
});

export default ParticipateToPartsRule;
