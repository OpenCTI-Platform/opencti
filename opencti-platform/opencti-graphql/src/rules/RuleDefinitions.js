import AttributedToAttributedDef from './attributed-to-attributed/AttributedToAttributedDefinition';
import ObservableRelatedDef from './observable-related/ObservableRelatedDefinition';
import ConfidenceLevelDef from './confidence-level/ConfidenceLevelDefinition';
import RelatedToRelatedDef from './related-to-related/RelatedToRelatedDefinition';
import AttributionUseDef from './attribution-use/AttributionUseDefinition';

const declaredDef = [
  AttributionUseDef,
  AttributedToAttributedDef,
  ObservableRelatedDef,
  ConfidenceLevelDef,
  RelatedToRelatedDef,
];
export default declaredDef;
