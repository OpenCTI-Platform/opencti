import React, { FunctionComponent } from 'react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { CONFIG_IMPORT_MODE_LABELS, ConfigImportMode, DEFAULT_CONFIG_IMPORT_MODE, isConfigImportMode } from '../configImportMode';

interface ConfigPresetImportModeSelectProps {
  typeLabel: string;
  // The modes the type supports, the choice is shown from two
  modes: ReadonlyArray<string>;
  value?: ConfigImportMode;
  disabled?: boolean;
  onChange: (mode: ConfigImportMode) => void;
}

// What the import does with the items of a type that already exist, on the row of the type; nothing for a type with no choice
const ConfigPresetImportModeSelect: FunctionComponent<ConfigPresetImportModeSelectProps> = ({
  typeLabel,
  modes,
  value = DEFAULT_CONFIG_IMPORT_MODE,
  disabled,
  onChange,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const supported = modes.filter(isConfigImportMode);
  if (supported.length < 2) {
    return null;
  }
  const label = t_i18n('When it already exists');
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
      <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{label}</Text>
      <Select value={value} disabled={disabled} onValueChange={(mode) => onChange(mode as ConfigImportMode)}>
        <SelectTrigger aria-label={`${typeLabel}: ${label}`}>
          <SelectValue>{t_i18n(CONFIG_IMPORT_MODE_LABELS[value])}</SelectValue>
        </SelectTrigger>
        <SelectContent aria-label={`${typeLabel}: ${label}`}>
          {supported.map((mode) => <SelectItem key={mode} value={mode}>{t_i18n(CONFIG_IMPORT_MODE_LABELS[mode])}</SelectItem>)}
        </SelectContent>
      </Select>
    </div>
  );
};

export default ConfigPresetImportModeSelect;
