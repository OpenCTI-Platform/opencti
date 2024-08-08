/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent, useMemo } from 'react';
import { PreloadedQuery, graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import Loader, { LoaderVariant } from 'src/components/Loader';
import { Link, Route, Routes, useLocation, useParams } from 'react-router-dom';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import ErrorNotFound from 'src/components/ErrorNotFound';
import { Box, Tab, Tabs } from '@mui/material';
import StixCoreObjectOrStixCoreRelationshipContainers from '@components/common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectHistory from '@components/common/stix_core_objects/StixCoreObjectHistory';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootFinancialDataQuery } from './__generated__/RootFinancialDataQuery.graphql';
import StixCyberObservableKnowledge from '../stix_cyber_observables/StixCyberObservableKnowledge';
import StixCyberObservableHeader from '../stix_cyber_observables/StixCyberObservableHeader';
import FinancialData from './FinancialData';
import { RootFinancialDataSubscription } from './__generated__/RootFinancialDataSubscription.graphql';
import Breadcrumbs from '../../../../components/Breadcrumbs';

const subscription = graphql`
  subscription RootFinancialDataSubscription($id: ID!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableEditionContainer_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
    }
  }
`;

const financialDataQuery = graphql`
  query RootFinancialDataQuery($id: String!) {
    stixCyberObservable(id: $id) {
      id
      standard_id
      entity_type
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableHeader_stixCyberObservable
      ...StixCyberObservableDetails_stixCyberObservable
      ...StixCyberObservableIndicators_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
      ...FinancialData_financialAccount
      ...FinancialData_financialAsset
      ...FinancialData_financialTransaction
    }
  }
`;

interface RootFinancialDataComponentProps {
  queryRef: PreloadedQuery<RootFinancialDataQuery, Record<string, unknown>>,
  financialDataId: string
}

const RootFinancialDataComponent: FunctionComponent<
RootFinancialDataComponentProps
> = ({
  queryRef,
  financialDataId,
}) => {
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootFinancialDataSubscription>
  >(
    () => ({
      subscription,
      variables: { id: financialDataId },
    }),
    [financialDataId],
  );
  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription(subConfig);
  const { stixCyberObservable } = usePreloadedQuery(financialDataQuery, queryRef);
  const basepath = '/dashboard/observations/financial-data/';
  return (
    <>
      {stixCyberObservable ? (
        <div
          style={{
            paddingRight: location.pathname.includes(
              `${basepath}${financialDataId}/knowledge`,
            )
              ? 200
              : 0,
          }}
          data-testid="financialData-details-page"
        >
          <Breadcrumbs variant="object" elements={[
            { label: t_i18n('Observations') },
            { label: t_i18n('Financial Data'), link: '/dashboard/observations/financial-data' },
            { label: stixCyberObservable.observable_value, current: true },
          ]}
          />
          <StixCyberObservableHeader
            stixCyberObservable={stixCyberObservable}
            isArtifact={false}
            disableSharing={false}
          />
          <Box
            sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 4 }}
          >
            <Tabs
              value={
                location.pathname.includes(
                  `${basepath}${stixCyberObservable.id}/knowledge`,
                )
                  ? `${basepath}${stixCyberObservable.id}/knowledge`
                  : location.pathname
              }
            >
              <Tab
                component={Link}
                to={`${basepath}${financialDataId}`}
                value={`${basepath}${financialDataId}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`${basepath}${stixCyberObservable.id}/knowledge`}
                value={`${basepath}${stixCyberObservable.id}/knowledge`}
                label={t_i18n('Knowledge')}
              />
              <Tab
                component={Link}
                to={`${basepath}${financialDataId}/analyses`}
                value={`${basepath}${financialDataId}/analyses`}
                label={t_i18n('Analyses')}
              />
              <Tab
                component={Link}
                to={`${basepath}${financialDataId}/history`}
                value={`${basepath}${financialDataId}/history`}
                label={t_i18n('History')}
              />
            </Tabs>
          </Box>
          <Routes>
            <Route
              path="/"
              element={<FinancialData data={stixCyberObservable} />}
            />
            <Route
              path="/knowledge"
              element={
                <StixCyberObservableKnowledge
                  stixCyberObservable={stixCyberObservable}
                />
              }
            />
            <Route
              path="/analyses/*"
              element={
                <StixCoreObjectOrStixCoreRelationshipContainers
                  stixDomainObjectOrStixCoreRelationship={stixCyberObservable}
                />
              }
            />
            <Route
              path="/history"
              element={
                <StixCoreObjectHistory
                  stixCoreObjectId={financialDataId}
                />
              }
            />
          </Routes>
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </>
  );
};

const RootFinancialData = () => {
  const { financialDataId } = useParams() as { financialDataId: string };
  const queryRef = useQueryLoading<RootFinancialDataQuery>(
    financialDataQuery,
    { id: financialDataId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootFinancialDataComponent
            queryRef={queryRef}
            financialDataId={financialDataId}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default RootFinancialData;
