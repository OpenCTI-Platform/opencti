import { graphql } from 'relay-runtime';
import { getCurrentTab } from '../../../utils/utils';
import type { CustomView } from './CustomViews-types';
import { useCustomViewsData } from './useCustomViewsData';

export const DEFAULT_CUSTOM_VIEW_TAB_VALUE = 'default-custom-view';

export const CUSTOM_VIEW_TAB_VALUE = 'custom-view';

export const customViewsFragment = graphql`
  fragment useCustomViews_data on Query
  @refetchable(queryName: "UseCustomViewsRefetchQuery") {
    customViews(
      orderBy: name
      orderMode: asc
      filters: {
        mode: and
        filters: [{
          key: ["enabled"]
          values: [true]
        }]
        filterGroups: []
      }
    ) {
      edges {
        node {
          id
          name
          path
          targetEntityType
          default
        }
      }
    }
  }
`;

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

export const useCustomViews = (entityType: string) => {
  const { allCustomViews } = useCustomViewsData();
  const customViews = allCustomViews.filter(
    ({ targetEntityType }) => targetEntityType === entityType,
  );
  if (!customViews) {
    return NO_CUSTOM_VIEWS;
  }
  const getCurrentCustomViewTab = matchPath(customViews);
  return { customViews, getCurrentCustomViewTab };
};
