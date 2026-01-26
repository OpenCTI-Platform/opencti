/* eslint-disable camelcase */
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import def from './ReportRefObservableBelongsToDefinition';
import buildContainerRefsRule from '../containerWithRefsBuilder';
import { RELATION_BELONGS_TO } from '../../schema/stixCoreRelationship';

/**
 * Rule: If Container A object-ref (contains) Observable B, If Observable B belongs to Observable C,
 * Then Container A object-ref (contains) Observable C
 *
 * Pattern:
 * - Report A contains Observable B (object_refs)
 * - Observable B belongs-to Observable C
 * - Result: Report A contains Observable C and the belongs-to relation
 */
const ReportRefObservableBelongsToRule = buildContainerRefsRule(def, ENTITY_TYPE_CONTAINER_REPORT, {
  leftType: ABSTRACT_STIX_CYBER_OBSERVABLE,
  rightType: ABSTRACT_STIX_CYBER_OBSERVABLE,
  creationType: RELATION_BELONGS_TO,
});

export default ReportRefObservableBelongsToRule;
