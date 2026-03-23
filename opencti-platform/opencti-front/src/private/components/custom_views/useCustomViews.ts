import useAuth from '../../../utils/hooks/useAuth';
import useHelper from '../../../utils/hooks/useHelper';

export const useCustomViews = (entityType: string) => {
  const { isFeatureEnable } = useHelper();
  const isCustomViewFeatureEnabled = isFeatureEnable('CUSTOM_VIEW');
  const { customViewsDisplayContext } = useAuth();
  if (!isCustomViewFeatureEnabled) {
    return {
      customViews: [],
    };
  }
  const customViewsContextForType = customViewsDisplayContext.find(({ entity_type }) => entity_type === entityType);
  if (!customViewsContextForType) {
    return {
      customViews: [],
    };
  }
  return {
    customViews: customViewsContextForType.custom_views_info ?? [],
  };
};
