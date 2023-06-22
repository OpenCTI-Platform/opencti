import React, { FunctionComponent, useMemo } from 'react';
import { Route, Switch, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
import { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { RootSettingsOrganizationQuery } from './__generated__/RootSettingsOrganizationQuery.graphql';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import SettingsOrganization from './SettingsOrganization';
import { RootSettingsOrganizationSubscription } from './__generated__/RootSettingsOrganizationSubscription.graphql';

const subscription = graphql`
  subscription RootSettingsOrganizationSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Organization {
        ...SettingsOrganization_organization
      }
    }
  }
`;

const organizationQuery = graphql`
  query RootSettingsOrganizationQuery($id: String!) {
    organization(id: $id) {
      id
      name
      x_opencti_aliases
      ...SettingsOrganization_organization
    }
  }
`;
interface RootSettingsOrganizationComponentProps {
  queryRef: PreloadedQuery<RootSettingsOrganizationQuery>,
  organizationId: string,
}
const RootSettingsOrganizationComponent: FunctionComponent<RootSettingsOrganizationComponentProps> = ({ queryRef, organizationId }) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootSettingsOrganizationSubscription>>(
    () => ({
      subscription,
      variables: { id: organizationId },
    }),
    [organizationId],
  );
  useSubscription(subConfig);
  const data = usePreloadedQuery(organizationQuery, queryRef);
  const { organization } = data;
  return (
    <Security needs={[SETTINGS_SETACCESSES]}>
      {organization ? (
        <Switch>
          <Route
            exact
            path="/dashboard/settings/accesses/organizations/:organizationId"
            render={(routeProps) => (
              <SettingsOrganization {...routeProps} organizationData={organization} />
            )}
          />
        </Switch>
      ) : (
        <ErrorNotFound />
      )}
    </Security>
  );
};
const RootSettingsOrganization = () => {
  const { organizationId } = useParams() as { organizationId: string };
  const queryRef = useQueryLoading<RootSettingsOrganizationQuery>(organizationQuery, { id: organizationId });
  return (
    <div>
      <TopBar />
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <RootSettingsOrganizationComponent queryRef={queryRef} organizationId={organizationId}/>
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </div>
  );
};
export default RootSettingsOrganization;
