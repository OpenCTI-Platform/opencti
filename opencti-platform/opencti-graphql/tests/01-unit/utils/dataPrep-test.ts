import { convertIpAddr } from '../../../src/utils/dataPrep';
import { exclusionListEntityType, type ExclusionListProperties } from '../../../src/utils/exclusionListTypes';
import * as exclusionList from '../../data/exclusionList/index';

const STORE_EXCLUSION_LIST = [
  exclusionList.vpnIpv4List,
  exclusionList.vpnIpv6List,
  exclusionList.publicDnsHostNameList, // test
  exclusionList.publicDnsV4List,
  exclusionList.publicDnsV6List,
  exclusionList.openaiGptBotList,
  exclusionList.captivePortalsList,
  exclusionList.bankWebsiteList,
  exclusionList.googleBotList,
];

const STORE_EXCLUSION_LIST_BINARY = [];

export const convertAndFillExclusionList = () => {
  STORE_EXCLUSION_LIST.forEach((item: ExclusionListProperties) => {
    if (item.type.includes(exclusionListEntityType.IPV4_ADDR) || item.type.includes(exclusionListEntityType.IPV6_ADDR)) {
      const newList = convertIpAddr(item.list);
      STORE_EXCLUSION_LIST_BINARY.push({ ...item, list: newList });
      return;
    }
    STORE_EXCLUSION_LIST_BINARY.push(item);
  });
};
