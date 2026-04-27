import { graphql, loadQuery, type PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { environment } from '../../../relay/environment';
import type { useCustomViewsDataQuery } from './__generated__/useCustomViewsDataQuery.graphql';

const customViewsDataQuery = graphql`
  query useCustomViewsDataQuery($entityType: String) {
    customViews(
      entityType: $entityType
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

const customViewsDataQueryRefs = new Map<string, PreloadedQuery<useCustomViewsDataQuery>>();

const getCustomViewsDataQueryRef = (entityType: string) => {
  const existingRef = customViewsDataQueryRefs.get(entityType);
  if (existingRef) {
    return existingRef;
  }

  const nextRef = loadQuery<useCustomViewsDataQuery>(
    environment,
    customViewsDataQuery,
    { entityType },
    { fetchPolicy: 'store-or-network' },
  );
  customViewsDataQueryRefs.set(entityType, nextRef);
  return nextRef;
};

export const invalidateCustomViewsData = (entityType?: string) => {
  if (entityType) {
    const ref = customViewsDataQueryRefs.get(entityType);
    ref?.dispose();
    customViewsDataQueryRefs.delete(entityType);
    return;
  }

  customViewsDataQueryRefs.forEach((ref) => ref.dispose());
  customViewsDataQueryRefs.clear();
};

export const useCustomViewsData = (entityType: string) => {
  const queryRef = getCustomViewsDataQueryRef(entityType);
  const data = usePreloadedQuery<useCustomViewsDataQuery>(
    customViewsDataQuery,
    queryRef,
  );
  const customViews = data?.customViews.edges.map((e) => e.node) ?? [];
  return { customViews };
};
