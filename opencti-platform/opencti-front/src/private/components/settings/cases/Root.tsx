/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Redirect, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useAuth from '../../../../utils/hooks/useAuth';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Case from './Case';
import { RootCasesSubscription } from './__generated__/RootCasesSubscription.graphql';
import { RootCaseQuery } from './__generated__/RootCaseQuery.graphql';

const subscription = graphql`
  subscription RootCasesSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Case {
        ...Case_case
      }
    }
  }
`;

const caseQuery = graphql`
  query RootCaseQuery($id: String!) {
    case(id: $id) {
      ...Case_case
    }
  }
`;

const RootCaseComponent = ({ queryRef }) => {
  const { me } = useAuth();
  const { caseId } = useParams() as { caseId: string };

  const subConfig = useMemo<GraphQLSubscriptionConfig<RootCasesSubscription>>(() => ({
    subscription,
    variables: { id: caseId },
  }), [caseId]);
  useSubscription(subConfig);

  const { case: caseData } = usePreloadedQuery<RootCaseQuery>(caseQuery, queryRef);

  return (
    <div>
      <TopBar me={me} />
      <>
        {caseData ? (
          <Switch>
            <Route
              exact
              path="/dashboard/settings/managements/feedback/:caseId"
              render={() => (<Case data={caseData} />)}
            />
            <Route
              exact
              path="/dashboard/settings/managements/feedback/:caseId/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/settings/managements/feedback/${caseId}/knowledge/overview`}
                />
              )}
            />
          </Switch>
        ) : <ErrorNotFound />}
      </>
    </div>
  );
};

const RootCase = () => {
  const { caseId } = useParams() as { caseId: string };

  const queryRef = useQueryLoading<RootCaseQuery>(caseQuery, { id: caseId });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <RootCaseComponent queryRef={queryRef} />
    </React.Suspense>
  ) : <Loader variant={LoaderVariant.inElement} />;
};

export default RootCase;
