export const isStixCyberObservables = (stixCoreObjectTypes) => stixCoreObjectTypes?.includes('Stix-Cyber-Observable');
export const isStixCoreObjects = (stixCoreObjectTypes) => !stixCoreObjectTypes || stixCoreObjectTypes.includes('Stix-Core-Object');

export const computeTargetStixDomainObjectTypes = (stixCoreObjectTypes) => {
  const finalStixCoreObjectTypes = stixCoreObjectTypes || ['Stix-Core-Object'];
  const stixCoreObjectTypesWithoutObservables = finalStixCoreObjectTypes.filter((n) => n !== 'Stix-Cyber-Observable');
  return stixCoreObjectTypesWithoutObservables.includes('Stix-Core-Object')
    ? ['Stix-Domain-Object']
    : stixCoreObjectTypesWithoutObservables;
};
export const computeTargetStixCyberObservableTypes = (stixCoreObjectTypes) => {
  const finalStixCoreObjectTypes = stixCoreObjectTypes || ['Stix-Core-Object'];
  return finalStixCoreObjectTypes.includes('Stix-Core-Object')
  || finalStixCoreObjectTypes.includes('Stix-Cyber-Observable')
    ? ['Stix-Cyber-Observable']
    : null;
};
