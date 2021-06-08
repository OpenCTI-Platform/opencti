import AttributedToAttributedRule from './attributed-to-attributed/AttributedToAttributedRule';
import ObservableRelated from './observable-related/ObservableRelatedRule';
import ConfidenceLevel from './confidence-level/ConfidenceLevelRule';
import RelatedToRelatedRule from './related-to-related/RelatedToRelatedRule';

const declaredRules = [AttributedToAttributedRule, ObservableRelated, ConfidenceLevel, RelatedToRelatedRule];
export default declaredRules;
