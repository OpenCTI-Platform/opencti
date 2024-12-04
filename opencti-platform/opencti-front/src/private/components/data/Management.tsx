import React from 'react';
import ManagementMenu from '@components/data/ManagementMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useHelper from '../../../utils/hooks/useHelper';

const Management = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isNewManagementScreensEnables = isFeatureEnable('NEW_MANAGEMENT_SCREENS');

  return (
    <div data-testid='data-management-page'>
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Management') }, { label: t_i18n('Restricted entities'), current: true }]}/>
      {isNewManagementScreensEnables && (
      <ManagementMenu />
      )}
    </div>
  );
};

export default Management;
