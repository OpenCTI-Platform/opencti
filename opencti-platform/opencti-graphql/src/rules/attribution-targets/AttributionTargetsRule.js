/* eslint-disable camelcase */
import { RELATION_ATTRIBUTED_TO, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import def from './AttributionTargetsDefinition';
import buildRelationWithRelationRule from '../relationWithRelationBuilder';
import { RULES_DECLARATION } from '../rules';

const AttributionTargetsRule = buildRelationWithRelationRule(def, {
  leftType: RELATION_TARGETS,
  rightType: RELATION_ATTRIBUTED_TO,
  creationType: RELATION_TARGETS,
});

RULES_DECLARATION.push(AttributionTargetsRule);
