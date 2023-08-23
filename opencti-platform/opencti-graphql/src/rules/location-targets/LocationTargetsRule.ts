/* eslint-disable camelcase */
import { RELATION_LOCATED_AT, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import def from './LocationTargetsDefinition';
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RULES } from '../rules';

const LocationTargetsRule = buildRelationToRelationRule(def, {
  leftType: RELATION_TARGETS,
  rightType: RELATION_LOCATED_AT,
  creationType: RELATION_TARGETS,
});

RULES.push(LocationTargetsRule);
