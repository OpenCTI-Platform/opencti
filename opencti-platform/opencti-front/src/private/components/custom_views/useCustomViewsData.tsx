import { createContext, PropsWithChildren, useContext, useMemo } from 'react';
import { useRefetchableFragment } from 'react-relay';
import type { useCustomViews_data$key } from './__generated__/useCustomViews_data.graphql';
import type { UseCustomViewsRefetchQuery } from './__generated__/UseCustomViewsRefetchQuery.graphql';
import { customViewsFragment } from './useCustomViews';

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

export const useCustomViewsData = () => {
  const { preloadedData } = useContext(CustomViewsPreloadedDataContext);
  const [data, refetch] = useRefetchableFragment<
    UseCustomViewsRefetchQuery,
    useCustomViews_data$key
  >(customViewsFragment, preloadedData);
  const allCustomViews = data?.customViews.edges.map((e) => e.node) ?? [];
  const refetchCustomViews = () => refetch({}, { fetchPolicy: 'store-and-network' });
  return { allCustomViews, refetchCustomViews };
};
