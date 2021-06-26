import AttributedToAttributedRule from './attributed-to-attributed/AttributedToAttributedRule';
import ObservableRelated from './observable-related/ObservableRelatedRule';
import AttributionUseRule from './attribution-use/AttributionUseRule';
import AttributionTargetsRule from './attribution-targets/AttributionTargetsRule';
import LocationTargetsRule from './location-targets/LocationTargetsRule';
import PartOfTargetsRule from './part-of-targets/PartOfTargetsRule';
import LocatedAtLocatedRule from './located-at-located/LocatedAtLocatedRule';
import RuleLocalizationOfTargetsRule from './localization-of-targets/LocalizationOfTargetsRule';
import ConfidenceLevelRule from './testing/confidence-level/ConfidenceLevelRule';
import RelatedToRelatedRule from './testing/related-to-related/RelatedToRelatedRule';
import { DEV_MODE } from '../config/conf';

const declaredRules = [
  AttributedToAttributedRule,
  ObservableRelated,
  AttributionUseRule,
  AttributionTargetsRule,
  LocationTargetsRule,
  PartOfTargetsRule,
  LocatedAtLocatedRule,
  RuleLocalizationOfTargetsRule,
];

if (DEV_MODE) {
  declaredRules.push(...[ConfidenceLevelRule, RelatedToRelatedRule]);
}
export default declaredRules;
