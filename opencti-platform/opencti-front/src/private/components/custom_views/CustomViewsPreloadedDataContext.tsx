import { createContext, PropsWithChildren, useMemo } from 'react';
import type { useCustomViews_data$key } from './__generated__/useCustomViews_data.graphql';

export interface CustomViewsPreloadedDataContext {
  preloadedData: useCustomViews_data$key | undefined;
}

const defaultContext = {
  preloadedData: undefined,
};

export const CustomViewsPreloadedDataContext = createContext<CustomViewsPreloadedDataContext>(defaultContext);

type CustomViewsPreloadedDataContextProviderProps = PropsWithChildren<{
  customViews: useCustomViews_data$key;
}>;

export const CustomViewsPreloadedDataContextProvider = (
  { customViews, children }: CustomViewsPreloadedDataContextProviderProps,
) => {
  const value = useMemo(() => ({ preloadedData: customViews }), [customViews]);
  return (
    <CustomViewsPreloadedDataContext.Provider value={value}>
      {children}
    </CustomViewsPreloadedDataContext.Provider>
  );
};
