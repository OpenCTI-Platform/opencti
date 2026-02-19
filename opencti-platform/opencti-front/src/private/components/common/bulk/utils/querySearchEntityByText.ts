export type StixCoreResultsType = {
  searchTerm: string;
  stixCoreObjects: EdgesType;
};
export type EdgesType = {
  edges: NodesType[];
};
type NodesType = {
  node: StixCoreEntityType;
};
type StixCoreEntityType = {
  entity_type: string;
  id: string;
  name: string;
  representative: StixRepresentative;
};

type StixRepresentative = {
  main: string;
};
