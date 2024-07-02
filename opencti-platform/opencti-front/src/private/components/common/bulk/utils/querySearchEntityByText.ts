export type StixCoreResultsType = {
  searchTerm: string;
  stixCoreObjects: EdgesType;
};
export type EdgesType = {
  edges: NodesType[];
};
export type NodesType = {
  node: StixCoreEntityType;
};
export type StixCoreEntityType = {
  entity_type: string;
  id: string;
  name: string;
  representative: StixRepresentative
};

export type StixRepresentative = {
  main: string;
};

export const allEntitiesKeyList = [
  'name',
  'aliases',
  'x_opencti_aliases',
  'x_mitre_id',
  'value',
  'subject',
  'attribute_abstract',
  'x_opencti_additional_names',
  // observables
  'iban',
  'hashes.MD5',
  'hashes.SHA-1',
  'hashes.SHA-256',
  'hashes.SHA-512',
  'url',
  'card_number',
  'value',
  'account_type',
  'user_id',
  'account_login',
  'path',
];
