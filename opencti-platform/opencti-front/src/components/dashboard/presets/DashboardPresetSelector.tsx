import { useState } from 'react';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import { Menu, MenuContent, MenuGroup, MenuItem, MenuLabel, MenuSeparator, MenuTrigger, Text } from '@filigran/design-system';
import { ArrowDropDownOutlined, ArrowDropUpOutlined, DeleteOutlined, EditOutlined } from '@mui/icons-material';
import { useFormatter } from '../../i18n';
import type { Theme } from '../../Theme';
import type { DashboardPreset } from '../dashboard-types';

interface DashboardPresetSelectorProps {
  presets: readonly DashboardPreset[];
  activePreset: DashboardPreset | null;
  defaultPreset: DashboardPreset | null;
  disabled?: boolean;
  onSelect: (presetId: string | null) => void;
  // The management of the active preset only exists when its callback is provided (editors).
  onRename?: (preset: DashboardPreset) => void;
  onDelete?: (preset: DashboardPreset) => void;
}

/**
 * The preset pill opening the bar of a dashboard: the view in use, and the menu to switch to another one. The editors
 * also rename and delete the active preset from there; saving lives in the Save menu of the bar.
 */
const DashboardPresetSelector = ({
  presets,
  activePreset,
  defaultPreset,
  disabled = false,
  onSelect,
  onRename,
  onDelete,
}: DashboardPresetSelectorProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [open, setOpen] = useState(false);
  // Nothing to switch to: the editor saves the first preset from the Save menu.
  if (presets.length === 0) return null;
  const secondaryText = { color: theme.palette.text.secondary };
  return (
    <Box data-testid="dashboard-preset-selector" sx={{ display: 'flex', alignItems: 'center' }}>
      <Menu open={open && !disabled} onOpenChange={setOpen} modal={false}>
        <MenuTrigger asChild>
          <Button
            variant="secondary"
            size="small"
            disabled={disabled}
            data-testid="dashboard-preset-trigger"
            endIcon={open ? <ArrowDropUpOutlined /> : <ArrowDropDownOutlined />}
          >
            <Text variant="content-caption" as="span" style={{ ...secondaryText, marginRight: 6 }}>
              {t_i18n('Preset')}
            </Text>
            {activePreset?.name ?? t_i18n('No preset')}
          </Button>
        </MenuTrigger>
        <MenuContent align="start" sideOffset={6} style={{ minWidth: 220 }}>
          <MenuGroup>
            <MenuLabel>{t_i18n('Presets')}</MenuLabel>
            {presets.map((preset) => (
              <MenuItem
                key={preset.id}
                data-testid={`dashboard-preset-option-${preset.id}`}
                selected={preset.id === activePreset?.id}
                onSelect={() => onSelect(preset.id)}
              >
                <span style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                  <span>{preset.name}</span>
                  {preset.id === defaultPreset?.id && (
                    <Text variant="content-caption" as="span" style={secondaryText}>
                      {t_i18n('Default')}
                    </Text>
                  )}
                </span>
              </MenuItem>
            ))}
            {/* Back to no preset: with a default preset, picking that one already does it. */}
            {defaultPreset === null && (
              <MenuItem
                data-testid="dashboard-preset-none"
                selected={activePreset === null}
                onSelect={() => onSelect(null)}
              >
                {t_i18n('No preset')}
              </MenuItem>
            )}
          </MenuGroup>
          {activePreset && (onRename || onDelete) && (
            <>
              <MenuSeparator />
              {onRename && (
                <MenuItem
                  data-testid="dashboard-preset-rename"
                  startIcon={<EditOutlined fontSize="small" />}
                  onSelect={() => onRename(activePreset)}
                >
                  {t_i18n('Rename “{name}”', { values: { name: activePreset.name } })}
                </MenuItem>
              )}
              {onDelete && (
                <MenuItem
                  data-testid="dashboard-preset-delete"
                  startIcon={<DeleteOutlined fontSize="small" />}
                  onSelect={() => onDelete(activePreset)}
                >
                  {t_i18n('Delete “{name}”', { values: { name: activePreset.name } })}
                </MenuItem>
              )}
            </>
          )}
        </MenuContent>
      </Menu>
    </Box>
  );
};

export default DashboardPresetSelector;
