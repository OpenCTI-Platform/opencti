import { useContext } from 'react';
import { useRefetchableFragment } from 'react-relay';
import type { useCustomViews_data$key } from './__generated__/useCustomViews_data.graphql';
import type { UseCustomViewsRefetchQuery } from './__generated__/UseCustomViewsRefetchQuery.graphql';
import { customViewsFragment } from './useCustomViews';
import { CustomViewsPreloadedDataContext } from './CustomViewsPreloadedDataContext';

export const useCustomViewsData = () => {
  const { preloadedData } = useContext(CustomViewsPreloadedDataContext);
  if (!preloadedData) {
    throw new Error('CustomViews preloaded data is unavailable');
  }
  const [data, refetch] = useRefetchableFragment<
    UseCustomViewsRefetchQuery,
    useCustomViews_data$key
  >(customViewsFragment, preloadedData);
  const allCustomViews = data?.customViews.edges.map((e) => e.node) ?? [];
  const refetchCustomViews = () => refetch({}, { fetchPolicy: 'store-and-network' });
  return { allCustomViews, refetchCustomViews };
};
