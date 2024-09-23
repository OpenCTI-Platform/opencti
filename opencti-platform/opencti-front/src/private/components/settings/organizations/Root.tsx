// TODO remove this when v6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent, useMemo } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import AccessesMenu from '@components/settings/AccessesMenu';
import { SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { RootSettingsOrganizationQuery } from './__generated__/RootSettingsOrganizationQuery.graphql';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import SettingsOrganization from './SettingsOrganization';
import { RootSettingsOrganizationSubscription } from './__generated__/RootSettingsOrganizationSubscription.graphql';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';

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
      standard_id
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
  const { t_i18n } = useFormatter();

  return (
    <Security needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}>
      {organization ? (
        <>
          <AccessesMenu/>
          <Breadcrumbs elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Security') },
            { label: t_i18n('Organizations'), link: '/dashboard/settings/accesses/organizations' },
            { label: organization.name, current: true },
          ]}
          />
          <Routes>
            <Route
              path="/"
              element={
                <SettingsOrganization organizationData={organization}/>
            }
            />
          </Routes>
        </>
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
