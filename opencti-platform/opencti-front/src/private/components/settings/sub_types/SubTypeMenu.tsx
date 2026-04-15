import { Tab, Tabs } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';

interface SubTypeMenuProps {
  entityType: string;
  isFINTELTemplatesEnabled?: boolean;
  isAttributesConfigurationEnabled?: boolean;
  isWorkflowConfigurationEnabled?: boolean;
  isCustomOverviewLayoutEnabled?: boolean;
}

const SubTypeMenu = ({
  entityType,
  isFINTELTemplatesEnabled,
  isAttributesConfigurationEnabled,
  isWorkflowConfigurationEnabled,
  isCustomOverviewLayoutEnabled,
}: SubTypeMenuProps) => {
  const { t_i18n } = useFormatter();
  const location = useLocation();

  const hasAtLeastOneEnabledTab = Boolean(
    isWorkflowConfigurationEnabled
    || isAttributesConfigurationEnabled
    || isFINTELTemplatesEnabled
    || isCustomOverviewLayoutEnabled,
  );

  if (!hasAtLeastOneEnabledTab) return null;

  return (
    <Tabs
      value={location.pathname}
      sx={{ paddingBottom: 2 }}
    >
      {isWorkflowConfigurationEnabled && (
        <Tab
          component={Link}
          to={`/dashboard/settings/customization/entity_types/${entityType}/workflow`}
          value={`/dashboard/settings/customization/entity_types/${entityType}/workflow`}
          label={t_i18n('Workflow')}
        />
      )}

      {
        isAttributesConfigurationEnabled && (
          <Tab
            component={Link}
            to={`/dashboard/settings/customization/entity_types/${entityType}/attributes`}
            value={`/dashboard/settings/customization/entity_types/${entityType}/attributes`}
            label={t_i18n('Attributes')}
          />
        )
      }

      {isFINTELTemplatesEnabled && (
        <Tab
          component={Link}
          to={`/dashboard/settings/customization/entity_types/${entityType}/templates`}
          value={`/dashboard/settings/customization/entity_types/${entityType}/templates`}
          label={t_i18n('Templates')}
        />
      )}

      {isCustomOverviewLayoutEnabled && (
        <Tab
          component={Link}
          to={`/dashboard/settings/customization/entity_types/${entityType}/overview-layout`}
          value={`/dashboard/settings/customization/entity_types/${entityType}/overview-layout`}
          label={t_i18n('Overview Layout')}
        />
      )}
    </Tabs>
  );
};

export default SubTypeMenu;
