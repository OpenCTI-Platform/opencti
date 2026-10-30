import React, { FunctionComponent } from 'react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import { CONFIG_IMPORT_MODE_LABELS, ConfigImportMode, isConfigImportMode } from '../configImportMode';

interface ConfigPresetImportModeSelectProps {
  // What the choice is about: an item, or a type for the choice of all its items
  subject: string;
  // The modes the type supports, the choice is shown from two
  modes: ReadonlyArray<string>;
  // null: the items it stands for have different modes
  value: ConfigImportMode | null;
  // The accessible name next to the subject
  purpose: 'When it already exists' | 'Apply to all';
  disabled?: boolean;
  onChange: (mode: ConfigImportMode) => void;
}

// What the import does with an item that already exists, on its row, or with all those of a type, on the row of the type;
// nothing for a type with no choice
const ConfigPresetImportModeSelect: FunctionComponent<ConfigPresetImportModeSelectProps> = ({
  subject,
  modes,
  value,
  purpose,
  disabled,
  onChange,
}) => {
  const { t_i18n } = useFormatter();
  const supported = modes.filter(isConfigImportMode);
  if (supported.length < 2) {
    return null;
  }
  const label = `${subject}: ${t_i18n(purpose)}`;
  return (
    <Select value={value ?? ''} disabled={disabled} onValueChange={(mode) => onChange(mode as ConfigImportMode)}>
      <SelectTrigger aria-label={label}>
        <SelectValue placeholder={t_i18n('Mixed')}>{value ? t_i18n(CONFIG_IMPORT_MODE_LABELS[value]) : null}</SelectValue>
      </SelectTrigger>
      <SelectContent aria-label={label}>
        {supported.map((mode) => <SelectItem key={mode} value={mode}>{t_i18n(CONFIG_IMPORT_MODE_LABELS[mode])}</SelectItem>)}
      </SelectContent>
    </Select>
  );
};

export default ConfigPresetImportModeSelect;
