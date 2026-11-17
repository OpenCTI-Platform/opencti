import { RELATION_IMPLEMENTS_TECHNIQUE, RELATION_USES } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import def, { USING_TYPES } from './ProcedureTechniqueUseDefinition';
import buildRelationToRelationRule from '../relationToRelationBuilder';

const ProcedureTechniqueUseRule = buildRelationToRelationRule(def, {
  leftType: RELATION_USES,
  rightType: RELATION_IMPLEMENTS_TECHNIQUE,
  creationType: RELATION_USES,
  leftTypesFrom: USING_TYPES,
  rightTypesTo: [ENTITY_TYPE_ATTACK_PATTERN],
});

export default ProcedureTechniqueUseRule;
