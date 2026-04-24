import { useEffect, type ReactNode } from 'react';
import { graphql } from 'relay-runtime';
import { PreloadedQuery, useQueryLoader } from 'react-relay';
import { CustomViewsQueryLoader_Query } from './__generated__/CustomViewsQueryLoader_Query.graphql';

export type CustomViewsPreloadedQuery = PreloadedQuery<CustomViewsQueryLoader_Query>;

export const customViewsQuery = graphql`
  query CustomViewsQueryLoader_Query($entityType: String) {
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
          enabled
          default
        }
      }
    }
  }
`;

interface CustomViewsQueryLoaderProps {
  entityType: string;
  render: (props: { queryRef: CustomViewsPreloadedQuery }) => ReactNode;
};

const CustomViewsQueryLoader = ({ entityType, render }: CustomViewsQueryLoaderProps) => {
  const [queryReference, loadQuery] = useQueryLoader<CustomViewsQueryLoader_Query>(
    customViewsQuery,
  );
  useEffect(() => {
    loadQuery({ entityType });
  }, [entityType]);
  return queryReference && render({ queryRef: queryReference });
};

export default CustomViewsQueryLoader;
