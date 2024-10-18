export enum exclusionListEntityType {
  IPV4_ADDR = 'IPv4-Addr',
  IPV6_ADDR = 'IPv6-Addr',
  DOMAIN_NAME = 'Domain-Name',
  URL = 'Url',
}

export type ExclusionListProperties = {
  name: string;
  type: exclusionListEntityType[];
  list: string[];
  actions: null;
};

export type ExtractedObservableValues = {
  type: string;
  value: string;
};
