export const getGroupOrOrganizationMapping = (sourceList: string[], targetList: string[]) => {
  if (sourceList.length !== targetList.length || sourceList.length === 0 || targetList.length === 0) return [];
  return sourceList.map((source, index) => `${source}:${targetList[index]}`);
};
