import React from 'react';
import { Tabs, Tab } from '@mui/material';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';

interface SubTypeMenuProps {
  entityType: string;
}

const SubTypeMenu = ({ entityType }: SubTypeMenuProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Tabs value={location.pathname} sx={{ paddingBottom: 3 }}>
      <Tab
        component={Link}
        to={`/dashboard/settings/customization/entity_types/${entityType}`}
        value={`/dashboard/settings/customization/entity_types/${entityType}`}
        label={t_i18n('Overview')}
      />
      <Tab
        component={Link}
        to={`/dashboard/settings/customization/entity_types/${entityType}/workflow`}
        value={`/dashboard/settings/customization/entity_types/${entityType}/workflow`}
        label={t_i18n('Workflow')}
      />
    </Tabs>
  );
};

export default SubTypeMenu;
