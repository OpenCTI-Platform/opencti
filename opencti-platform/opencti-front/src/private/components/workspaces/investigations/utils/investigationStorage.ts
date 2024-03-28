export const investigationPreExpansionStateListStorageKey = 'preExpansionStateList';

type UpdatePreExpansionStateParamsType = Array<{
  dateTime: number;
  investigatedEntitiesIdsList: string[];
}>;
export const getPreExpansionStateList = () => sessionStorage.getItem(investigationPreExpansionStateListStorageKey);

export const updatePreExpansionStateList = (preExpansionStateList: UpdatePreExpansionStateParamsType) => {
  preExpansionStateList.shift();
  if (preExpansionStateList.length === 0) {
    sessionStorage.removeItem(investigationPreExpansionStateListStorageKey);
  } else {
    sessionStorage.setItem(investigationPreExpansionStateListStorageKey, JSON.stringify(preExpansionStateList));
  }
};
