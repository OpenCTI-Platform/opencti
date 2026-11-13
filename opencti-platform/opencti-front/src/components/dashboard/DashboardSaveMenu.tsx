import { type ReactNode, useState } from 'react';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger, Text } from '@filigran/design-system';
import { AddOutlined, ArrowDropDownOutlined, ArrowDropUpOutlined, DashboardCustomizeOutlined, SaveOutlined } from '@mui/icons-material';
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
  // An entry closes the menu itself: it starts a save that disables the menu, and a menu closed only by being
  // disabled would open again once the save is done.
  const closeThen = (action?: () => void) => () => {
    setOpen(false);
    action?.();
  };
  // Each entry says for whom it writes, under its action: no group label (its narrower inset would not line up).
  const withAudience = (label: string, audience: string): ReactNode => (
    <span style={{ display: 'flex', flexDirection: 'column', gap: 2, padding: '4px 0' }}>
      <span>{label}</span>
      <Text variant="content-compact" as="span" style={{ color: theme.palette.text.secondary }}>{audience}</Text>
    </span>
  );
  const entries: ReactNode[] = [];
  if (activePresetName !== undefined && onUpdatePreset) {
    entries.push(
      <MenuItem
        key="preset"
        data-testid="dashboard-preset-update"
        startIcon={<SaveOutlined fontSize="small" />}
        disabled={!canUpdatePreset}
        onSelect={closeThen(onUpdatePreset)}
      >
        {withAudience(t_i18n('Update “{name}”', { values: { name: activePresetName } }), t_i18n('For everyone using this preset'))}
      </MenuItem>,
    );
  }
  if (onSavePresetAs) {
    entries.push(
      <MenuItem key="new" data-testid="dashboard-preset-save-as" startIcon={<AddOutlined fontSize="small" />} onSelect={closeThen(onSavePresetAs)}>
        {withAudience(t_i18n('Save as new preset…'), t_i18n('Under a new name, for anyone to pick'))}
      </MenuItem>,
    );
  }
  if (onSetAsDefaults) {
    entries.push(
      <MenuItem
        key="defaults"
        data-testid="dashboard-set-as-defaults"
        startIcon={<DashboardCustomizeOutlined fontSize="small" />}
        disabled={!canSetAsDefaults}
        onSelect={closeThen(onSetAsDefaults)}
      >
        {withAudience(t_i18n('Set as dashboard defaults'), t_i18n('For everyone without a preset'))}
      </MenuItem>,
    );
  }
  if (entries.length === 0) return null;
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
      <MenuContent align="end" sideOffset={6} style={{ minWidth: 280 }}>
        {entries.flatMap((entry, index) => (index === 0 ? [entry] : [<MenuSeparator key={`separator-${index}`} />, entry]))}
      </MenuContent>
    </Menu>
  );
};

export default DashboardSaveMenu;
