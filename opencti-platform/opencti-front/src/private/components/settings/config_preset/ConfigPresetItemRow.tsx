import React, { FunctionComponent, ReactNode } from 'react';
import { Checkbox, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { ConfigPresetForcedItems, ConfigPresetSelection, isConfigPresetItemSelected, toggleConfigPresetItem } from './configPresetSelection';

export interface ConfigPresetItem {
  readonly key: string;
  readonly label: string;
  readonly translatable: boolean;
  readonly isDefault: boolean;
}

export interface ConfigPresetSelectionProps {
  selection: ConfigPresetSelection;
  forced: ConfigPresetForcedItems;
  onSelectionChange: (selection: ConfigPresetSelection) => void;
}

interface ConfigPresetItemRowProps extends ConfigPresetSelectionProps {
  typeKey: string;
  item: ConfigPresetItem;
  // Shown on the right of the row, after the tag (the expected result of a simulated import)
  statusSlot?: ReactNode;
  // Disables the checkbox, as a forced dependency is
  disabled?: boolean;
  // Under the label: what the item is, when it stands for its type
  description?: string;
}

// A forced dependency is checked and disabled
export const ConfigPresetItemRow: FunctionComponent<ConfigPresetItemRowProps> = ({
  typeKey,
  item,
  selection,
  forced,
  onSelectionChange,
  statusSlot,
  disabled = false,
  description,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const isForced = (forced[typeKey] ?? []).includes(item.key);
  const tags = item.isDefault ? [t_i18n('default')] : [];
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1) }}>
      <Checkbox
        label={item.translatable ? t_i18n(item.label) : item.label}
        description={description}
        checked={isForced || isConfigPresetItemSelected(selection, typeKey, item.key)}
        disabled={isForced || disabled}
        onCheckedChange={(checked) => onSelectionChange(toggleConfigPresetItem(selection, typeKey, item.key, checked === true))}
      />
      {(tags.length > 0 || statusSlot) && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: theme.spacing(1) }}>
          {tags.length > 0 && (
            <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{tags.join(' · ')}</Text>
          )}
          {statusSlot}
        </div>
      )}
    </div>
  );
};
