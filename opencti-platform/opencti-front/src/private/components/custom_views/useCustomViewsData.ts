import { useRefetchableFragment } from 'react-relay';
import useAuth from '../../../utils/hooks/useAuth';
import type { useCustomViews_data$key } from './__generated__/useCustomViews_data.graphql';
import type { UseCustomViewsRefetchQuery } from './__generated__/UseCustomViewsRefetchQuery.graphql';
import { customViewsFragment } from './useCustomViews';

export const useCustomViewsData = () => {
  const { queryData } = useAuth();
  const [data, refetch] = useRefetchableFragment<
    UseCustomViewsRefetchQuery,
    useCustomViews_data$key
  >(customViewsFragment, queryData);
  const allCustomViews = data?.customViews.edges.map((e) => e.node) ?? [];
  const refetchCustomViews = () => refetch({}, { fetchPolicy: 'store-and-network' });
  return { allCustomViews, refetchCustomViews };
};
