import Stack from '@mui/material/Stack';
import { BookmarkAddOutlined, DeleteOutlined, EditOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import { IconButton, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../i18n';
import { EXPORT_REMOVE_CLASS } from '../../../utils/Image';
import type { DashboardPreset } from '../dashboard-types';

export interface DashboardPresetSelectorProps {
  presets: readonly DashboardPreset[];
  activePreset: DashboardPreset | null;
  // The preset the dashboard opens on for this user (their own choice, their group or organization).
  defaultPreset: DashboardPreset | null;
  // The current values differ from the ones of the active preset: it can be updated.
  isModified: boolean;
  // Create, update, rename and delete: editors of the dashboard only.
  canManage: boolean;
  disabled?: boolean;
  onSelect: (presetId: string | null) => void;
  onSaveAs?: () => void;
  onUpdate?: () => void;
  onRename?: (preset: DashboardPreset) => void;
  onDelete?: (preset: DashboardPreset) => void;
}

/**
 * The preset selector of a dashboard: switching restores the values and the time range of the preset at once.
 * Presentational: the page wires the callbacks.
 */
const DashboardPresetSelector = ({
  presets,
  activePreset,
  defaultPreset,
  isModified,
  canManage,
  disabled = false,
  onSelect,
  onSaveAs,
  onUpdate,
  onRename,
  onDelete,
}: DashboardPresetSelectorProps) => {
  const { t_i18n } = useFormatter();
  const label = t_i18n('Preset');
  // The library shows its clear control only with a value and when enabled (Select.tsx, canClear).
  const hasClearControl = presets.length > 0 && !!activePreset && !disabled;
  return (
    <Stack
      direction="row"
      data-testid="dashboard-preset-selector"
      className={EXPORT_REMOVE_CLASS}
      sx={{
        alignItems: 'center',
        gap: 1,
      }}
    >
      {presets.length > 0 && (
        // FDS-WORKAROUND #77: with its clear control, the library Select wrapper is 32px narrower than its trigger, so
        // the chevron overflows onto the next sibling of a flex row - see fds-migration/LIBRARY-FEEDBACK.md #77
        <span data-testid="dashboard-preset-select" style={{ display: 'inline-flex', paddingRight: hasClearControl ? 32 : 0 }}>
          <Select
            value={activePreset?.id ?? ''}
            // The clear control of the trigger empties the selection: back to no preset.
            onValueChange={(value) => onSelect(value === '' ? null : value)}
            clearable
            clearLabel={t_i18n('No preset')}
            disabled={disabled}
            name="dashboard-preset"
          >
            <SelectTrigger aria-label={label} data-testid="dashboard-preset-trigger">
              <SelectValue placeholder={label} />
            </SelectTrigger>
            <SelectContent aria-label={label}>
              {presets.map((preset) => (
                <SelectItem key={preset.id} value={preset.id}>
                  {preset.id === defaultPreset?.id ? t_i18n('{name} (default)', { values: { name: preset.name } }) : preset.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </span>
      )}
      {canManage && activePreset && isModified && onUpdate && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="secondary"
              size="small"
              data-testid="dashboard-preset-update"
              disabled={disabled}
              onClick={onUpdate}
            >
              {t_i18n('Update preset')}
            </Button>
          </TooltipTrigger>
          <TooltipContent>{t_i18n('The current values and time range differ from this preset: save them into it')}</TooltipContent>
        </Tooltip>
      )}
      {canManage && onSaveAs && (
        <Button
          variant="tertiary"
          size="small"
          data-testid="dashboard-preset-save-as"
          startIcon={<BookmarkAddOutlined />}
          disabled={disabled}
          onClick={onSaveAs}
        >
          {t_i18n('Save as preset')}
        </Button>
      )}
      {canManage && activePreset && onRename && (
        <IconButton
          variant="default"
          priority="tertiary"
          size="sm"
          aria-label={t_i18n('Rename preset')}
          data-testid="dashboard-preset-rename"
          disabled={disabled}
          onClick={() => onRename(activePreset)}
          icon={<EditOutlined fontSize="small" />}
        />
      )}
      {canManage && activePreset && onDelete && (
        <IconButton
          variant="default"
          priority="tertiary"
          size="sm"
          aria-label={t_i18n('Delete preset')}
          data-testid="dashboard-preset-delete"
          disabled={disabled}
          onClick={() => onDelete(activePreset)}
          icon={<DeleteOutlined fontSize="small" />}
        />
      )}
    </Stack>
  );
};

export default DashboardPresetSelector;
