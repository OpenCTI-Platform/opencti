/* eslint-disable camelcase */
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import def from './ReportRefIdentityPartOfDefinition';
import buildContainerRefsRule from '../containerWithRefsBuilder';
import { RELATION_PART_OF } from '../../schema/stixCoreRelationship';
import { RULES } from '../rules';

const ReportRefsIdentityPartOfRule = buildContainerRefsRule(def, ENTITY_TYPE_CONTAINER_REPORT, {
  leftType: ENTITY_TYPE_IDENTITY,
  rightType: ENTITY_TYPE_IDENTITY,
  creationType: RELATION_PART_OF,
});

RULES.push(ReportRefsIdentityPartOfRule);
export default ReportRefsIdentityPartOfRule;
