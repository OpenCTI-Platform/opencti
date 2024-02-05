import type { BasicStoreCommon } from './store';
import type { ConfidenceLevel } from '../generated/graphql';

interface DefaultMarking {
  entity_type: string,
  values: Array<string>
}

interface Group extends BasicStoreCommon {
  default_marking?: Array<DefaultMarking>;
  group_confidence_level: ConfidenceLevel
}
