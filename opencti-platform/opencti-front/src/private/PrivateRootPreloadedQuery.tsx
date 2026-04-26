import { ReactNode, Suspense } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { graphql } from 'relay-runtime';
import Loader from '../components/Loader';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import { PrivateRootPreloadedQuery, PrivateRootPreloadedQuery$data } from './__generated__/PrivateRootPreloadedQuery.graphql';
import { CustomViewsPreloadedDataContextProvider } from '@components/custom_views/useCustomViewsData';
import { PlatformModulesHelperPreloadedDataContextProvider } from '../utils/platformModulesHelper';
import { SchemaPreloadedDataContextProvider } from '../utils/schema/SchemaPreloadedContext';

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
    ...platformModulesHelper_settings @alias(as: "platformModulesHelper")
    ...useSchema_data @alias(as: "schema")
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
    <PlatformModulesHelperPreloadedDataContextProvider preloadedData={queryData.platformModulesHelper}>
      <SchemaPreloadedDataContextProvider preloadedData={queryData.schema}>
        <CustomViewsPreloadedDataContextProvider customViews={queryData.customViews}>
          {render({ queryData })}
        </CustomViewsPreloadedDataContextProvider>
      </SchemaPreloadedDataContextProvider>
    </PlatformModulesHelperPreloadedDataContextProvider>
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
