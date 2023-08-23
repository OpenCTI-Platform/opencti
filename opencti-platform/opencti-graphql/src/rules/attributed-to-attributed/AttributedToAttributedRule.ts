/* eslint-disable camelcase */
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RELATION_ATTRIBUTED_TO } from '../../schema/stixCoreRelationship';
import def from './AttributedToAttributedDefinition';
import { RULES } from '../rules';

const AttributedToAttributedRule = buildRelationToRelationRule(def, {
  leftType: RELATION_ATTRIBUTED_TO,
  rightType: RELATION_ATTRIBUTED_TO,
  creationType: RELATION_ATTRIBUTED_TO,
});

RULES.push(AttributedToAttributedRule);
