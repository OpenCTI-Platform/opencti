import AttributedToAttributedRule from './attributed-to-attributed/AttributedToAttributedRule';
import ObservableRelated from './observable-related/ObservableRelatedRule';
import ConfidenceLevel from './confidence-level/ConfidenceLevelRule';
import RelatedToRelatedRule from './related-to-related/RelatedToRelatedRule';
import AttributionUseRule from './attribution-use/AttributionUseRule';

const declaredRules = [
  AttributionUseRule,
  AttributedToAttributedRule,
  ObservableRelated,
  ConfidenceLevel,
  RelatedToRelatedRule,
];
export default declaredRules;
