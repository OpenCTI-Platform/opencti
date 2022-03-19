interface StixBasicObject {
  x_opencti_id: string;
  entity_type: string;
}

interface StixObject extends StixBasicObject {
  x_opencti_stix_ids: Array<string>;
}

interface StixMetaObject extends StixObject {
  created: Date;
  modified: Date;
}

interface StixCoreObject extends StixObject {
  created_by_ref: string;
  object_marking_refs: Array<string> | [];
}

interface StoreStixDomainObject extends StixCoreObject {
  confidence: number;
}

interface StixContainer extends StoreStixDomainObject {
  object_refs: Array<string> | [];
}

interface StoreStixRelation extends StixObject {
  relationship_type: string;
  x_opencti_source_ref: string;
  x_opencti_target_ref: string;
}

interface StoreObservedData extends StixContainer {
  confidence: number;
  first_observed: Date;
  last_observed: Date;
  number_observed: number;
  name: string;
}

type StixEntities = StoreObservedData;
