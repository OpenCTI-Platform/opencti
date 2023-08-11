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
import { RootAccountQuery } from './__generated__/RootAccountQuery.graphql';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Account from './Account';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import AccountPopover from './AccountPopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import AccountKnowledge from './AccountKnowledge';

const subscription = graphql`
  subscription RootAccountSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on FinancialAccount {
        ...Account_financialAccount
      }
    }
  }
`;

const accountQuery = graphql`
  query RootAccountQuery($id: ID!) {
    financialAccount(id: $id) {
      id
      name: name
      ...Account_financialAccount
      ...AccountKnowledge_financialAccount
    }
  }
`;

const RootAccountComponent = ({ queryRef, accountId }) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootAccountSubscription>>(
    () => ({
      subscription,
      variables: { id: accountId },
    }),
    [accountId],
  );
  useSubscription(subConfig);
  const data = usePreloadedQuery(accountQuery, queryRef);
  const { financialAccount } = data;
  return (
    <>
      {financialAccount ? (
        <Switch>
          <Route
            exact
            path="/dashboard/financial/accounts/:accountId"
            render={() => <Account accountData={financialAccount} />}
          />
          <Route
            exact
            path="/dashboard/financial/accounts/:accountId/knowledge"
            render={() => (
              <Redirect
                to={`/dashboard/financial/accounts/${accountId}/knowledge/overview`}
              />
            )}
          />
          <Route
            path="/dashboard/financial/accounts/:accountId/knowledge"
            render={() => <AccountKnowledge accountData={financialAccount} />}
          />
          <Route
            exact
            path="/dashboard/financial/accounts/:accountId/history"
            render={(routeProps: any) => (
              <React.Fragment>
                <StixDomainObjectHeader
                  disableSharing={true}
                  stixDomainObject={financialAccount}
                  PopoverComponent={<AccountPopover id={financialAccount.id} />}
                />
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={accountId}
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

const RootAccount = () => {
  const { accountId } = useParams() as { accountId: string };
  const queryRef = useQueryLoading<RootAccountQuery>(accountQuery, {
    id: accountId,
  });
  const link = `/dashboard/financial/accounts/${accountId}/knowledge`;
  return (
    <div>
      <TopBar />
      <Route path="/dashboard/financial/accounts/:accountId/knowledge">
        <StixCoreObjectKnowledgeBar
          stixCoreObjectLink={link}
          availableSections={[
            'individuals',
            'organizations',
            'threat_actors',
          ]}
        />
      </Route>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <RootAccountComponent queryRef={queryRef} accountId={accountId} link={link} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </div>
  );
};

export default RootAccount;
