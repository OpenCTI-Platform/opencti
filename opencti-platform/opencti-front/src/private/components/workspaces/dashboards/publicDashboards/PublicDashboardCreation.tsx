import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import React, { Suspense, useEffect } from 'react';
import PublicDashboardCreationForm, { dashboardsQuery } from '@components/workspaces/dashboards/publicDashboards/PublicDashboardCreationForm';
import { useQueryLoader } from 'react-relay';
import { PublicDashboardCreationFormDashboardsQuery } from '@components/workspaces/dashboards/publicDashboards/__generated__/PublicDashboardCreationFormDashboardsQuery.graphql';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { PublicDashboardsListQuery$variables } from '@components/workspaces/dashboards/publicDashboards/__generated__/PublicDashboardsListQuery.graphql';
import { useFormatter } from '../../../../../components/i18n';
import useHelper from '../../../../../utils/hooks/useHelper';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import CreateEntityControlledDial from '../../../../../components/CreateEntityControlledDial';
import { insertNode } from '../../../../../utils/store';

const PublicDashboardCreateDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial entityType='Public-Dashboard' {...props} />
);

interface PublicDashboardCreationProps {
  paginationOptions: PublicDashboardsListQuery$variables
}

const PublicDashboardCreation = ({ paginationOptions }: PublicDashboardCreationProps) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();

  const [dashboardsQueryRef, fetchDashboards] = useQueryLoader<PublicDashboardCreationFormDashboardsQuery>(dashboardsQuery);
  const fetchDashboardsWithFilters = () => {
    fetchDashboards(
      {
        filters: {
          mode: 'and',
          filterGroups: [],
          filters: [{
            key: ['type'],
            values: ['dashboard'],
          }],
        },
      },
      { fetchPolicy: 'store-and-network' },
    );
  };

  useEffect(() => {
    fetchDashboardsWithFilters();
  }, []);

  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_publicDashboards',
    paginationOptions,
    'publicDashboardAdd',
  );

  return (
    <Drawer
      title={t_i18n('Create a public dashboard')}
      variant={isFeatureEnable('FAB_REPLACEMENT') ? undefined : DrawerVariant.create}
      controlledDial={isFeatureEnable('FAB_REPLACEMENT') ? PublicDashboardCreateDial : undefined}
    >
      {({ onClose }) => (
        <>
          {dashboardsQueryRef && (
            <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
              <PublicDashboardCreationForm
                updater={updater}
                queryRef={dashboardsQueryRef}
                onCancel={onClose}
                onCompleted={() => {
                  onClose();
                }}
              />
            </Suspense>
          )}
        </>
      )}
    </Drawer>
  );
};

export default PublicDashboardCreation;
