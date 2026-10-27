import React, { FunctionComponent, ReactNode } from 'react';
import { Checkbox, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
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
  // The item needs the Enterprise Edition: without it the row is disabled and unchecked, with a chip that opens the license dialog.
  // Separate from forced, which means checked and disabled.
  requiresEnterpriseEdition?: boolean;
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
  requiresEnterpriseEdition = false,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const isEnterpriseEdition = useEnterpriseEdition();
  const isLocked = requiresEnterpriseEdition && !isEnterpriseEdition;
  const isForced = (forced[typeKey] ?? []).includes(item.key);
  const tags = item.isDefault ? [t_i18n('default')] : [];
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1) }}>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Checkbox
          label={item.translatable ? t_i18n(item.label) : item.label}
          checked={!isLocked && (isForced || isConfigPresetItemSelected(selection, typeKey, item.key))}
          disabled={isForced || disabled || isLocked}
          onCheckedChange={(checked) => onSelectionChange(toggleConfigPresetItem(selection, typeKey, item.key, checked === true))}
        />
        {isLocked && <EEChip size="sm" />}
      </div>
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
