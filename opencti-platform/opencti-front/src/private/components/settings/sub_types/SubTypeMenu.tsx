import { Tab, Tabs } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';

interface SubTypeMenuProps {
  entityType: string;
  isFINTELTemplatesEnabled?: boolean;
  isAttributesConfigurationEnabled?: boolean;
  isWorkflowConfigurationEnabled?: boolean;
}

const SubTypeMenu = ({ entityType, isFINTELTemplatesEnabled, isAttributesConfigurationEnabled, isWorkflowConfigurationEnabled }: SubTypeMenuProps) => {
  const { t_i18n } = useFormatter();
  const location = useLocation();

  return (
    <Tabs
      value={location.pathname}
      sx={{ paddingBottom: 3 }}
    >
      <Tab
        component={Link}
        to={`/dashboard/settings/customization/entity_types/${entityType}`}
        value={`/dashboard/settings/customization/entity_types/${entityType}`}
        label={t_i18n('Overview')}
      />

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
    </Tabs>
  );
};

export default SubTypeMenu;
