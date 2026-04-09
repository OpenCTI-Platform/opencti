import { Tab, Tabs } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import type { SubTypeTabs } from './SubTypeOutletContext';

interface SubTypeMenuProps {
  entityType: string;
  tabs: SubTypeTabs;
}

const SubTypeMenu = ({ entityType, tabs }: SubTypeMenuProps) => {
  const { t_i18n } = useFormatter();
  const location = useLocation();

  const hasAtLeastOneEnabledTab = Object.values(tabs).some(Boolean);

  if (!hasAtLeastOneEnabledTab) return null;

  return (
    <Tabs
      value={location.pathname}
      sx={{ paddingBottom: 2 }}
    >
      {tabs.workflow && (
        <Tab
          component={Link}
          to={`/dashboard/settings/customization/entity_types/${entityType}/workflow`}
          value={`/dashboard/settings/customization/entity_types/${entityType}/workflow`}
          label={t_i18n('Workflow')}
        />
      )}

      {
        tabs.attributes && (
          <Tab
            component={Link}
            to={`/dashboard/settings/customization/entity_types/${entityType}/attributes`}
            value={`/dashboard/settings/customization/entity_types/${entityType}/attributes`}
            label={t_i18n('Attributes')}
          />
        )
      }

      {tabs.templates && (
        <Tab
          component={Link}
          to={`/dashboard/settings/customization/entity_types/${entityType}/templates`}
          value={`/dashboard/settings/customization/entity_types/${entityType}/templates`}
          label={t_i18n('Templates')}
        />
      )}

      {tabs['overview-layout'] && (
        <Tab
          component={Link}
          to={`/dashboard/settings/customization/entity_types/${entityType}/overview-layout`}
          value={`/dashboard/settings/customization/entity_types/${entityType}/overview-layout`}
          label={t_i18n('Overview Layout')}
        />
      )}

      {tabs['custom-views'] && (
        <Tab
          component={Link}
          to={`/dashboard/settings/customization/entity_types/${entityType}/custom-views`}
          value={`/dashboard/settings/customization/entity_types/${entityType}/custom-views`}
          label={t_i18n('Custom Views')}
        />
      )}
    </Tabs>
  );
};

export default SubTypeMenu;
