/* eslint-disable camelcase */
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_LOCATION } from '../../schema/general';
import def from './ReportRefLocationLocatedAtDefinition';
import buildContainerRefsRule from '../containerWithRefsBuilder';
import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';

const ReportRefsLocationLocatedAtRule = buildContainerRefsRule(def, ENTITY_TYPE_CONTAINER_REPORT, {
  leftType: ENTITY_TYPE_LOCATION,
  rightType: ENTITY_TYPE_LOCATION,
  creationType: RELATION_LOCATED_AT,
});

export default ReportRefsLocationLocatedAtRule;
