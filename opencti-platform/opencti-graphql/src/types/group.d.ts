import type { BasicStoreCommon } from './store';

interface DefaultMarking {
  entity_type: string,
  values: Array<string>
}

interface Group extends BasicStoreCommon {
  default_marking?: Array<DefaultMarking>;
}
