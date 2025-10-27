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
