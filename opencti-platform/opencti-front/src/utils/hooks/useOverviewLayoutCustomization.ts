import useAuth from './useAuth';

const useOverviewLayoutCustomization: (entityType: string) => { key: string, width: number, label: string }[] = (entityType) => {
  const { overviewLayoutCustomization } = useAuth();
  return overviewLayoutCustomization.get(entityType) ?? [];
};

export default useOverviewLayoutCustomization;
