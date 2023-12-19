/* eslint-disable camelcase */
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import def from './ReportRefObservableBasedOnDefinition';
import buildContainerRefsRule from '../containerWithRefsBuilder';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_INDICATOR } from '../../modules/indicator/indicator-types';

const ReportRefsObservableBasedOnRule = buildContainerRefsRule(def, ENTITY_TYPE_CONTAINER_REPORT, {
  leftType: ENTITY_TYPE_INDICATOR,
  rightType: ABSTRACT_STIX_CYBER_OBSERVABLE,
  creationType: RELATION_BASED_ON,
  isSource: false,
});

export default ReportRefsObservableBasedOnRule;
