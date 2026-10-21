import React, { useState } from 'react';
import { DashboardCustomizeOutlined } from '@mui/icons-material';
import { IconButton, Menu, MenuContent, MenuItem, MenuTrigger } from '@filigran/design-system';
import { useFormatter } from '../../i18n';
import { buildDashboardTemplateFile, DASHBOARD_TEMPLATES } from './dashboardTemplates';

interface DashboardTemplateMenuProps {
  onCreate: (file: File) => void;
}

/** "Create from template": builds the dashboard of a built-in template and hands it to the dashboard import. */
const DashboardTemplateMenu = ({ onCreate }: DashboardTemplateMenuProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  if (DASHBOARD_TEMPLATES.length === 0) {
    return null;
  }
  return (
    <Menu open={open} onOpenChange={setOpen}>
      <MenuTrigger asChild>
        <IconButton
          priority="secondary"
          aria-label={t_i18n('Create from template')}
          data-testid="CreateDashboardFromTemplate"
          icon={<DashboardCustomizeOutlined fontSize="small" />}
        />
      </MenuTrigger>
      <MenuContent align="end">
        {DASHBOARD_TEMPLATES.map((template) => (
          <MenuItem
            key={template.id}
            data-testid={`dashboard-template-${template.id}`}
            onSelect={() => onCreate(buildDashboardTemplateFile(template, t_i18n))}
          >
            {t_i18n(template.label)}
          </MenuItem>
        ))}
      </MenuContent>
    </Menu>
  );
};

export default DashboardTemplateMenu;
