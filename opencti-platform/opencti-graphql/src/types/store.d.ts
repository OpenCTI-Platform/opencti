interface StoreBasicObject {
  internal_id: string;
  standard_id: string;
  entity_type: string;
  parent_types: Array<string>;
}

interface StoreMarkingDefinition {
  internal_id: string;
  standard_id: string;
  definition_type: string;
}
