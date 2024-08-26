import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import React from 'react';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { PublicDashboardsListQuery$variables } from '@components/workspaces/dashboards/public_dashboards/__generated__/PublicDashboardsListQuery.graphql';
import PublicDashboardCreationForm from '@components/workspaces/dashboards/public_dashboards/PublicDashboardCreationForm';
import { useFormatter } from '../../../../../components/i18n';
import useHelper from '../../../../../utils/hooks/useHelper';
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
        <PublicDashboardCreationForm
          updater={updater}
          onCancel={onClose}
          onCompleted={onClose}
        />
      )}
    </Drawer>
  );
};

export default PublicDashboardCreation;
