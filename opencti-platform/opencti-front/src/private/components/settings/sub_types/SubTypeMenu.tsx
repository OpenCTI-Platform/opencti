import { Tab, Tabs } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import type { SubTypeTabs } from './SubTypeOutletContext';
import { getCurrentTab } from '../../../../utils/utils';

interface SubTypeMenuProps {
  entityType: string;
  tabs: SubTypeTabs;
}

const SubTypeMenu = ({ entityType, tabs }: SubTypeMenuProps) => {
  const { t_i18n } = useFormatter();
  const location = useLocation();

  const hasAtLeastOneEnabledTab = Object.values(tabs).some(Boolean);

  if (!hasAtLeastOneEnabledTab) return null;

  const currentTab = getCurrentTab(location.pathname, `/dashboard/settings/customization/entity_types/${entityType}`);

  return (
    <Tabs
      value={currentTab ?? 'workflow'}
      sx={{ paddingBottom: 2 }}
    >
      {tabs.workflow && (
        <Tab
          component={Link}
          to="workflow"
          value="workflow"
          label={t_i18n('Workflow')}
        />
      )}

      {
        tabs.attributes && (
          <Tab
            component={Link}
            to="attributes"
            value="attributes"
            label={t_i18n('Attributes')}
          />
        )
      }

      {tabs.templates && (
        <Tab
          component={Link}
          to="templates"
          value="templates"
          label={t_i18n('Templates')}
        />
      )}

      {tabs['overview-layout'] && (
        <Tab
          component={Link}
          to="overview-layout"
          value="overview-layout"
          label={t_i18n('Overview Layout')}
        />
      )}

      {tabs['custom-views'] && (
        <Tab
          component={Link}
          to="custom-views"
          value="custom-views"
          label={t_i18n('Custom Views')}
        />
      )}
    </Tabs>
  );
};

export default SubTypeMenu;
