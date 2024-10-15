export type IpAddrListType = { ipv4: string[], ipv6: string[] };

export type ExclusionListProperties = {
  name: string;
  type: string[ExclusionListEntityType];
  list: string[] | IpAddrListType;
  actions: null;
};

type ExclusionListEntityType = {
  [key: string]: string
};

export enum exclusionListEntityType {
  IPV4_ADDR = 'IPv4-Addr',
  IPV6_ADDR = 'IPv6-Addr',
  DOMAIN_NAME = 'Domain-Name',
  URL = 'Url',
  MAIL_ADDRESSES = 'MAIL_ADDRESSES',
}
