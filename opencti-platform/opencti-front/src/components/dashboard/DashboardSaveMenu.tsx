import { type ReactNode, useState } from 'react';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import { Menu, MenuContent, MenuGroup, MenuItem, MenuLabel, MenuSeparator, MenuTrigger, Text } from '@filigran/design-system';
import { ArrowDropDownOutlined, ArrowDropUpOutlined } from '@mui/icons-material';
import { useFormatter } from '../i18n';
import type { Theme } from '../Theme';
import { EXPORT_REMOVE_CLASS } from '../../utils/Image';

interface DashboardSaveMenuProps {
  // The name of the active preset: its update is only offered when one is active.
  activePresetName?: string;
  // The values or the range differ from the active preset.
  canUpdatePreset: boolean;
  // The values or the range differ from what the dashboard shows by default.
  canSetAsDefaults: boolean;
  disabled?: boolean;
  onUpdatePreset?: () => void;
  onSavePresetAs?: () => void;
  onSetAsDefaults?: () => void;
}

/**
 * The one Save of the dashboard bar, for the editors: each entry says for whom it writes. The active preset (everyone
 * using it), a new preset, or the dashboard defaults (everyone without a preset).
 */
const DashboardSaveMenu = ({
  activePresetName,
  canUpdatePreset,
  canSetAsDefaults,
  disabled = false,
  onUpdatePreset,
  onSavePresetAs,
  onSetAsDefaults,
}: DashboardSaveMenuProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [open, setOpen] = useState(false);
  const withSubtitle = (label: string, subtitle: string): ReactNode => (
    <span style={{ display: 'flex', flexDirection: 'column' }}>
      <span>{label}</span>
      <Text variant="content-caption" as="span" style={{ color: theme.palette.text.secondary }}>{subtitle}</Text>
    </span>
  );
  const groups: ReactNode[] = [];
  if (activePresetName !== undefined && onUpdatePreset) {
    groups.push(
      <MenuGroup key="preset">
        <MenuLabel>{t_i18n('Everyone using this preset')}</MenuLabel>
        <MenuItem data-testid="dashboard-preset-update" disabled={!canUpdatePreset} onSelect={onUpdatePreset}>
          {withSubtitle(t_i18n('Update “{name}”', { values: { name: activePresetName } }), t_i18n('Replace its values and time range'))}
        </MenuItem>
      </MenuGroup>,
    );
  }
  if (onSavePresetAs) {
    groups.push(
      <MenuGroup key="new">
        <MenuLabel>{t_i18n('New')}</MenuLabel>
        <MenuItem data-testid="dashboard-preset-save-as" onSelect={onSavePresetAs}>
          {t_i18n('Save as new preset…')}
        </MenuItem>
      </MenuGroup>,
    );
  }
  if (onSetAsDefaults) {
    groups.push(
      <MenuGroup key="defaults">
        <MenuLabel>{t_i18n('Everyone, without a preset')}</MenuLabel>
        <MenuItem data-testid="dashboard-set-as-defaults" disabled={!canSetAsDefaults} onSelect={onSetAsDefaults}>
          {withSubtitle(t_i18n('Set as dashboard defaults'), t_i18n('What the dashboard shows with no preset'))}
        </MenuItem>
      </MenuGroup>,
    );
  }
  if (groups.length === 0) return null;
  return (
    <Menu open={open && !disabled} onOpenChange={setOpen} modal={false}>
      <MenuTrigger asChild>
        <Button
          className={EXPORT_REMOVE_CLASS}
          variant="primary"
          size="small"
          disabled={disabled}
          data-testid="dashboard-save-menu"
          endIcon={open ? <ArrowDropUpOutlined /> : <ArrowDropDownOutlined />}
        >
          {t_i18n('Save')}
        </Button>
      </MenuTrigger>
      <MenuContent align="end" sideOffset={6} style={{ minWidth: 260 }}>
        {groups.flatMap((group, index) => (index === 0 ? [group] : [<MenuSeparator key={`separator-${index}`} />, group]))}
      </MenuContent>
    </Menu>
  );
};

export default DashboardSaveMenu;
