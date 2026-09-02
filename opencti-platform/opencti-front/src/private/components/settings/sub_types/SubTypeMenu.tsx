import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { Link, useLocation } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import type { SubTypeTabs } from './SubTypeOutletContext';
import { getCurrentTab } from '../../../../utils/tabUtils';

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
    <Tabs value={currentTab} panels="external">
      <TabsList className="pb-4">
        {tabs.workflow && (
          <TabsTrigger value="workflow" asChild>
            <Link to="workflow">{t_i18n('Workflow')}</Link>
          </TabsTrigger>
        )}
        {tabs.attributes && (
          <TabsTrigger value="attributes" asChild>
            <Link to="attributes">{t_i18n('Attributes')}</Link>
          </TabsTrigger>
        )}
        {tabs.templates && (
          <TabsTrigger value="templates" asChild>
            <Link to="templates">{t_i18n('Templates')}</Link>
          </TabsTrigger>
        )}
        {tabs['overview-layout'] && (
          <TabsTrigger value="overview-layout" asChild>
            <Link to="overview-layout">{t_i18n('Overview Layout')}</Link>
          </TabsTrigger>
        )}
        {tabs['custom-views'] && (
          <TabsTrigger value="custom-views" asChild>
            <Link to="custom-views">{t_i18n('Custom Views')}</Link>
          </TabsTrigger>
        )}
      </TabsList>
    </Tabs>
  );
};

export default SubTypeMenu;
