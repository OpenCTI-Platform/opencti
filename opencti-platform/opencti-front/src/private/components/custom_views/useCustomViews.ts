// import { graphql } from 'relay-runtime';
import { getCurrentTab } from '../../../utils/utils';
import type { CustomView } from './CustomViews-types';
// import { useCustomViewsData } from './useCustomViewsData';
import { useFragment, useLazyLoadQuery, usePreloadedQuery } from 'react-relay';
// import { useCustomViewsPaginationQuery } from './__generated__/useCustomViewsPaginationQuery.graphql';
// import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { CustomViewsPreloadedQuery, customViewsQuery } from './CustomViewsQueryLoader';

export const DEFAULT_CUSTOM_VIEW_TAB_VALUE = 'default-custom-view';

export const CUSTOM_VIEW_TAB_VALUE = 'custom-view';

// export const customViewsFragment = graphql`
//   fragment useCustomViews_data on Query
//   @refetchable(queryName: "UseCustomViewsRefetchQuery") {
//     customViews(
//       orderBy: name
//       orderMode: asc
//     ) {
//       edges {
//         node {
//           id
//           name
//           path
//           targetEntityType
//           enabled
//           default
//         }
//       }
//     }
//   }
// `;

// const customViewsQuery = graphql`
//   query useCustomViewsPaginationQuery($entityType: String) {
//     customViews(
//       orderBy: name
//       orderMode: asc
//       entityType: $entityType
//     ) {
//       edges {
//         node {
//           id
//           name
//           path
//           targetEntityType
//           enabled
//           default
//         }
//       }
//     }
//   }
// `;

function matchPath(customViews: CustomView[]) {
  return (fullPath: string, basePath: string) => {
    const current = getCurrentTab(fullPath, basePath);
    const currentCustomView = customViews.find(({ path }) => path === current);
    if (currentCustomView) {
      return currentCustomView.default
        ? DEFAULT_CUSTOM_VIEW_TAB_VALUE
        : CUSTOM_VIEW_TAB_VALUE;
    }
    return undefined;
  };
}

const NO_CUSTOM_VIEWS = {
  customViews: [],
  getCurrentCustomViewTab: () => undefined,
};

export const useCustomViews = (queryRef: CustomViewsPreloadedQuery) => {
  const data = usePreloadedQuery(customViewsQuery, queryRef);
  const customViews = data?.customViews?.edges.map((e) => e.node) ?? [];
  if (!customViews) {
    return NO_CUSTOM_VIEWS;
  }
  const nonNullCustomViews = customViews
    .filter((c) => !!c)
    .filter(({ enabled }) => enabled === true);
  const getCurrentCustomViewTab = matchPath(nonNullCustomViews);
  return { customViews: nonNullCustomViews, getCurrentCustomViewTab };
};
