import { graphql } from 'relay-runtime';
import { getCurrentTab } from '../../../utils/utils';
import type { CustomView } from './CustomViews-types';
import { useCustomViewsData } from './useCustomViewsData';
import { useLazyLoadQuery } from 'react-relay';
import { useCustomViewsPaginationQuery } from './__generated__/useCustomViewsPaginationQuery.graphql';

export const CUSTOM_VIEW_TAB_VALUE = 'custom-view';

export const customViewsFragment = graphql`
  fragment useCustomViews_data on Query
  @refetchable(queryName: "UseCustomViewsRefetchQuery") {
    customViews(
      orderBy: name
      orderMode: asc
    ) {
      edges {
        node {
          id
          name
          path
          targetEntityType
        }
      }
    }
  }
`;

const customViewsQuery = graphql`
  query useCustomViewsPaginationQuery($entityType: String) {
    customViews(
      orderBy: name
      orderMode: asc
      entityType: $entityType
    ) {
      edges {
        node {
          id
          name
          path
          targetEntityType
        }
      }
    }
  }
`;

function matchPath(customViews: CustomView[]) {
  return (fullPath: string, basePath: string) => {
    const current = getCurrentTab(fullPath, basePath);
    if (customViews.find(({ path }) => path === current)) {
      return CUSTOM_VIEW_TAB_VALUE;
    }
    return undefined;
  };
}

const NO_CUSTOM_VIEWS = {
  customViews: [],
  getCurrentCustomViewTab: () => undefined,
};

export const useCustomViews = (entityType: string) => {
  // const { allCustomViews } = useCustomViewsData();
  const data = useLazyLoadQuery<useCustomViewsPaginationQuery>(
    customViewsQuery,
    {
      entityType,
    },
    {
      fetchPolicy: 'store-or-network',
    });
  const customViews = data?.customViews?.edges.map((e) => e.node) ?? [];
  // const customViews = allCustomViews.filter(
  //   ({ targetEntityType }) => targetEntityType === entityType,
  // );
  if (!customViews) {
    return NO_CUSTOM_VIEWS;
  }
  const nonNullCustomViews = customViews
    .filter((c) => !!c)
    .filter(({ enabled }) => enabled === true);
  const getCurrentCustomViewTab = matchPath(nonNullCustomViews);
  return { customViews: nonNullCustomViews, getCurrentCustomViewTab };
};
