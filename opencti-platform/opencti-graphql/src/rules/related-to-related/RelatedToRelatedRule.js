/* eslint-disable camelcase */
import def from './RelatedToRelatedDefinition';
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { DEV_MODE } from '../../config/conf';
import { RULES_DECLARATION } from '../rules';

const RelatedToRelatedRule = buildRelationToRelationRule(def, {
  leftType: RELATION_RELATED_TO,
  rightType: RELATION_RELATED_TO,
  creationType: RELATION_RELATED_TO,
});

if (DEV_MODE) {
  RULES_DECLARATION.push(RelatedToRelatedRule);
}
