import { exclusionListEntityType, type ExclusionListProperties } from '../../../src/utils/exclusionListTypes';

const list = [
  '52.230.152.0/24',
  '52.233.106.0/24'
];

export const openaiGptBotList: ExclusionListProperties = {
  name: 'openaiGptBotList',
  type: [exclusionListEntityType.IPV4_ADDR],
  list,
  actions: null
};
