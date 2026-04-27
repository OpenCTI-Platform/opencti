import { ReactNode, Suspense } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { graphql } from 'relay-runtime';
import Loader from '../components/Loader';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import { PrivateRootPreloadedQuery, PrivateRootPreloadedQuery$data } from './__generated__/PrivateRootPreloadedQuery.graphql';
import { CustomViewsPreloadedDataContextProvider } from '@components/custom_views/useCustomViewsData';

const privateRootPreloadedQuery = graphql`
  query PrivateRootPreloadedQuery {
    me {
      ...RootMe_data
    }
    settings {
      ...RootSettings
    }
    about {
      version
    }
    entitySettings {
      edges {
        node {
          id
          ...EntitySettingsFragment_entitySetting
        }
      }
    }
    schemaSCOs: subTypes(type: "Stix-Cyber-Observable") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaSDOs: subTypes(type: "Stix-Domain-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaSMOs: subTypes(type: "Stix-Meta-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaSCRs: subTypes(type: "stix-core-relationship") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaRelationsTypesMapping {
      key
      values
    }
    schemaRelationsRefTypesMapping {
      key
      values {
        name
        toTypes
      }
    }
    filterKeysSchema {
      entity_type
      filters_schema {
        filterKey
        filterDefinition {
          filterKey
          label
          type
          multiple
          subEntityTypes
          elementsForFilterValuesSearch
          subFilters {
            filterKey
            label
            type
            multiple
            subEntityTypes
            elementsForFilterValuesSearch
          }
        }
      }
    }
    themes(orderBy: created_at, orderMode: desc) {
      edges {
        node {
          id
          name
          theme_background
          theme_accent
          theme_paper
          theme_nav
          theme_primary
          theme_secondary
          theme_text_color
          theme_logo
          theme_logo_collapsed
          theme_logo_login
        }
      }
    }
    ...useCustomViews_data @alias(as: "customViews")
  }
`;

interface PrivateRootPreloadedQueryDataProps {
  render: ({ queryData }: { queryData: PrivateRootPreloadedQuery$data }) => ReactNode;
  queryRef: PreloadedQuery<PrivateRootPreloadedQuery>;
};

const PrivateRootPreloadedQueryData = ({ queryRef, render }: PrivateRootPreloadedQueryDataProps) => {
  const queryData = usePreloadedQuery(privateRootPreloadedQuery, queryRef);
  return (
    <CustomViewsPreloadedDataContextProvider customViews={queryData.customViews}>
      {render({ queryData })}
    </CustomViewsPreloadedDataContextProvider>
  );
};

interface PrivateRootPreloadedQueryProps {
  render: ({ queryData }: { queryData: PrivateRootPreloadedQuery$data }) => ReactNode;
};

export const PrivateRootPreloadedQueryLoader = ({ render }: PrivateRootPreloadedQueryProps) => {
  const queryRef = useQueryLoading<PrivateRootPreloadedQuery>(privateRootPreloadedQuery);
  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader />}>
          <PrivateRootPreloadedQueryData queryRef={queryRef} render={render} />
        </Suspense>
      )}
    </>
  );
};
