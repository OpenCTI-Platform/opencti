import useAuth from './useAuth';

const useOverviewLayoutCustomization: (entityType: string) => Array<{ key: string, width: number }> = (entityType) => {
  const { overviewLayoutCustomization } = useAuth();
  return Array.from(overviewLayoutCustomization?.get(entityType)?.entries() ?? [])
    .flatMap(([key, width]) => ({ key, width }));
};

export default useOverviewLayoutCustomization;
