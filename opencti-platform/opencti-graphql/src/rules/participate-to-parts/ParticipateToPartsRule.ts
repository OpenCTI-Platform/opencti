/* eslint-disable camelcase */
import { RELATION_PART_OF } from '../../schema/stixCoreRelationship';
import def from './ParticipateToPartsDefinition';
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';
import { RULES } from '../rules';

const ParticipateToPartsRule = buildRelationToRelationRule(def, {
  leftType: RELATION_PARTICIPATE_TO,
  rightType: RELATION_PART_OF,
  creationType: RELATION_PARTICIPATE_TO,
});

RULES.push(ParticipateToPartsRule);
