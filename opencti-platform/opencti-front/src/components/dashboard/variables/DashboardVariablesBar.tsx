import { type ReactNode, useMemo, useState } from 'react';
import Box from '@mui/material/Box';
import Divider from '@mui/material/Divider';
import Stack from '@mui/material/Stack';
import { AddOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import { Badge } from '@filigran/design-system';
import { useFormatter } from '../../i18n';
import { EXPORT_REMOVE_CLASS } from '../../../utils/Image';
import type { DashboardVariable } from '../dashboard-types';
import { getInvalidDefaultVariableIds } from '../dashboardVariableDefaults';
import DashboardValuesActions from '../DashboardValuesActions';
import DashboardSaveMenu from '../DashboardSaveMenu';
import DashboardVariableChip from './DashboardVariableChip';
import { useVariablesValueLabels } from './useVariableValueLabels';

export interface DashboardVariablesBarProps {
  variables: readonly DashboardVariable[];
  // Effective values and their base (the active preset over the manifest defaults), by variable id.
  values: ReadonlyMap<string, string>;
  defaults: ReadonlyMap<string, string>;
  usedInWidgetIdsByVariable: ReadonlyMap<string, readonly string[]>;
  // An editor: gets the Save menu.
  canManage: boolean;
  // The actions also cover the time range of the dashboard: they show when it alone differs from its default.
  isTimeRangeModified?: boolean;
  // A preset other than the default one is active: Reset goes back to the default one.
  isPresetSelected?: boolean;
  // The preset Reset goes back to (the default one of the user); none: the dashboard defaults.
  resetTargetName?: string;
  // The active preset, and whether the values or the range differ from it: its update in the Save menu.
  activePresetName?: string;
  isActivePresetModified?: boolean;
  onSetValue: (variableId: string, value: string) => void;
  onReset: () => void;
  // Must not reject: the caller reports its own failures.
  onSetAsDefaults: () => Promise<void>;
  onUpdatePreset?: () => void;
  onSavePresetAs?: () => void;
  // Editing entry points: each one only exists when its callback is provided.
  onCreate?: () => void;
  onEdit?: (variable: DashboardVariable) => void;
  onDelete?: (variable: DashboardVariable) => void;
  // Rendered first in the bar: the preset pill of the dashboard.
  leading?: ReactNode;
}

// An unset variable (no default, no value) and an empty value are the same thing.
const isValueModified = (variableId: string, values: ReadonlyMap<string, string>, defaults: ReadonlyMap<string, string>) => (
  (values.get(variableId) ?? '') !== (defaults.get(variableId) ?? '')
);

/**
 * The context bar of a dashboard, on one row: which preset, which values, then what to do with them. The preset pill,
 * a Modified badge and a dot on each changed chip show the departure from the preset; Reset names what it restores;
 * the editors save through one menu that says for whom each entry writes. It never mutates anything by itself, the
 * page wires the callbacks.
 */
const DashboardVariablesBar = ({
  variables,
  values,
  defaults,
  usedInWidgetIdsByVariable,
  canManage,
  isTimeRangeModified = false,
  isPresetSelected = false,
  resetTargetName,
  activePresetName,
  isActivePresetModified = false,
  onSetValue,
  onReset,
  onSetAsDefaults,
  onUpdatePreset,
  onSavePresetAs,
  onCreate,
  onEdit,
  onDelete,
  leading,
}: DashboardVariablesBarProps) => {
  const { t_i18n } = useFormatter();
  const [isSubmitting, setIsSubmitting] = useState(false);
  // One query for the ids of all the chips, rather than one per chip.
  const valueLabels = useVariablesValueLabels(variables.map((variable) => ({ id: variable.id, variable, value: values.get(variable.id) })));

  const invalidDefaultIds = useMemo(() => getInvalidDefaultVariableIds(variables), [variables]);

  if (variables.length === 0 && !onCreate && !leading) return null;

  // Departed from the base (the active preset, else the dashboard defaults): what Modified and the chip dots show.
  const isDeparted = isTimeRangeModified || variables.some(({ id }) => isValueModified(id, values, defaults));
  // Reset also leaves a preset other than the default one, even unchanged.
  const isResettable = isDeparted || isPresetSelected;
  const handleSetAsDefaults = async () => {
    setIsSubmitting(true);
    try {
      await onSetAsDefaults();
    } finally {
      setIsSubmitting(false);
    }
  };
  const hasValuesSection = variables.length > 0 || onCreate !== undefined;

  return (
    <Stack
      data-testid="dashboard-variables-bar"
      direction="row"
      sx={{
        flexWrap: 'wrap',
        alignItems: 'center',
        gap: 1,
        marginBottom: 1.5,
      }}
    >
      {leading}
      {isDeparted && (
        <Badge
          data-testid="dashboard-values-modified"
          className={EXPORT_REMOVE_CLASS}
          tone="brand"
          content={t_i18n('Modified')}
        />
      )}
      {leading && hasValuesSection && (
        <Divider orientation="vertical" flexItem sx={{ marginX: 0.5 }} />
      )}
      {variables.map((variable) => (
        <DashboardVariableChip
          key={variable.id}
          variable={variable}
          value={values.get(variable.id)}
          valueLabels={valueLabels.get(variable.id)}
          disabled={isSubmitting}
          modified={isValueModified(variable.id, values, defaults)}
          hasInvalidDefault={invalidDefaultIds.has(variable.id)}
          usedInWidgetIds={usedInWidgetIdsByVariable.get(variable.id) ?? []}
          onChange={(value) => onSetValue(variable.id, value)}
          onEdit={onEdit}
          onDelete={onDelete}
        />
      ))}
      {onCreate && (
        <Button
          className={EXPORT_REMOVE_CLASS}
          data-testid="create-variable-button"
          variant="tertiary"
          size="small"
          startIcon={<AddOutlined />}
          onClick={onCreate}
        >
          {t_i18n('Variable')}
        </Button>
      )}
      <Box sx={{ flex: 1 }} />
      {isResettable && (
        <DashboardValuesActions resetTargetName={resetTargetName} disabled={isSubmitting} onReset={onReset} />
      )}
      {canManage && (
        <DashboardSaveMenu
          activePresetName={activePresetName}
          canUpdatePreset={isActivePresetModified}
          canSetAsDefaults={isResettable}
          disabled={isSubmitting}
          onUpdatePreset={onUpdatePreset}
          onSavePresetAs={onSavePresetAs}
          onSetAsDefaults={handleSetAsDefaults}
        />
      )}
    </Stack>
  );
};

export default DashboardVariablesBar;
