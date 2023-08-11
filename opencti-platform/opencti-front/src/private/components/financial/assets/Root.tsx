/* eslint-disable @typescript-eslint/no-explicit-any */
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { Redirect, Route, Switch, useParams } from 'react-router-dom';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import TopBar from '../../nav/TopBar';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RootAssetQuery } from './__generated__/RootAssetQuery.graphql';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Asset from './Asset';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import AssetPopover from './AssetPopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import AssetKnowledge from './AssetKnowledge';

const subscription = graphql`
  subscription RootAssetSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on FinancialAsset {
        ...Asset_financialAsset
      }
    }
  }
`;

const assetQuery = graphql`
  query RootAssetQuery($id: ID!) {
    financialAsset(id: $id) {
      id
      name: name
      ...Asset_financialAsset
      ...AssetKnowledge_financialAsset
    }
  }
`;

const RootAssetComponent = ({ queryRef, assetId }) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootAssetSubscription>>(
    () => ({
      subscription,
      variables: { id: assetId },
    }),
    [assetId],
  );
  useSubscription(subConfig);
  const data = usePreloadedQuery(assetQuery, queryRef);
  const { financialAsset } = data;
  return (
    <>
      {financialAsset ? (
        <Switch>
          <Route
            exact
            path="/dashboard/financial/assets/:assetId"
            render={() => <Asset assetData={financialAsset} />}
          />
          <Route
            exact
            path="/dashboard/financial/assets/:assetId/knowledge"
            render={() => (
              <Redirect
                to={`/dashboard/financial/assets/${assetId}/knowledge/overview`}
              />
            )}
          />
          <Route
            path="/dashboard/financial/assets/:assetId/knowledge"
            render={() => <AssetKnowledge assetData={financialAsset} />}
          />
          <Route
            exact
            path="/dashboard/financial/assets/:assetId/history"
            render={(routeProps: any) => (
              <React.Fragment>
                <StixDomainObjectHeader
                  disableSharing={true}
                  stixDomainObject={financialAsset}
                  PopoverComponent={<AssetPopover id={financialAsset.id} />}
                />
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={assetId}
                />
              </React.Fragment>
            )}
          />
        </Switch>
      ) : (
        <ErrorNotFound />
      )}
    </>
  );
};

const RootAsset = () => {
  const { assetId } = useParams() as { assetId: string };
  const queryRef = useQueryLoading<RootAssetQuery>(assetQuery, {
    id: assetId,
  });
  const link = `/dashboard/financial/assets/${assetId}/knowledge`;
  return (
    <div>
      <TopBar />
      <Route path="/dashboard/financial/assets/:assetId/knowledge">
        <StixCoreObjectKnowledgeBar
          stixCoreObjectLink={link}
          availableSections={[
            'individuals',
            'organizations',
            'threat_actors',
            'locations',
          ]}
        />
      </Route>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <RootAssetComponent queryRef={queryRef} assetId={assetId} link={link} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </div>
  );
};

export default RootAsset;
