import { useState } from 'react';
import Stack from '@mui/material/Stack';
import { AddOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import { useFormatter } from '../../i18n';
import { EXPORT_REMOVE_CLASS } from '../../../utils/Image';
import type { DashboardVariable } from '../dashboard-types';
import DashboardVariableChip from './DashboardVariableChip';
import { useVariablesValueLabels } from './useVariableValueLabels';

export interface DashboardVariablesBarProps {
  variables: readonly DashboardVariable[];
  // Effective values and manifest defaults, by variable id.
  values: ReadonlyMap<string, string>;
  defaults: ReadonlyMap<string, string>;
  usedInWidgetIdsByVariable: ReadonlyMap<string, readonly string[]>;
  // Allows setting the current values as the dashboard defaults.
  canManage: boolean;
  onSetValue: (variableId: string, value: string) => void;
  onReset: () => void;
  // Must not reject: the caller reports its own failures.
  onSetAsDefaults: () => Promise<void>;
  // Editing entry points: each one only exists when its callback is provided.
  onCreate?: () => void;
  onEdit?: (variable: DashboardVariable) => void;
  onDelete?: (variable: DashboardVariable) => void;
}

// An unset variable (no default, no value) and an empty value are the same thing.
const isModifiedFromDefaults = (
  variables: readonly DashboardVariable[],
  values: ReadonlyMap<string, string>,
  defaults: ReadonlyMap<string, string>,
) => variables.some(({ id }) => (values.get(id) ?? '') !== (defaults.get(id) ?? ''));

/**
 * Presentational bar of the dashboard variables: one chip per variable and the actions on the set of values.
 * It never mutates anything by itself, the page wires the callbacks.
 */
const DashboardVariablesBar = ({
  variables,
  values,
  defaults,
  usedInWidgetIdsByVariable,
  canManage,
  onSetValue,
  onReset,
  onSetAsDefaults,
  onCreate,
  onEdit,
  onDelete,
}: DashboardVariablesBarProps) => {
  const { t_i18n } = useFormatter();
  const [isSubmitting, setIsSubmitting] = useState(false);
  // One query for the ids of all the chips, rather than one per chip.
  const valueLabels = useVariablesValueLabels(variables.map((variable) => ({ id: variable.id, variable, value: values.get(variable.id) })));

  if (variables.length === 0 && !onCreate) return null;

  const isModified = isModifiedFromDefaults(variables, values, defaults);
  const handleSetAsDefaults = async () => {
    setIsSubmitting(true);
    try {
      await onSetAsDefaults();
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Stack
      data-testid="dashboard-variables-bar"
      direction="row"
      flexWrap="wrap"
      alignItems="center"
      gap={1}
      sx={{ marginBottom: 1.5 }}
    >
      {variables.map((variable) => (
        <DashboardVariableChip
          key={variable.id}
          variable={variable}
          value={values.get(variable.id)}
          valueLabels={valueLabels.get(variable.id)}
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
          {t_i18n('Create variable')}
        </Button>
      )}
      {isModified && (
        <>
          <Button
            className={EXPORT_REMOVE_CLASS}
            variant="tertiary"
            size="small"
            disabled={isSubmitting}
            onClick={onReset}
          >
            {t_i18n('Reset')}
          </Button>
          {canManage && (
            <Button
              className={EXPORT_REMOVE_CLASS}
              variant="secondary"
              size="small"
              disabled={isSubmitting}
              onClick={handleSetAsDefaults}
            >
              {t_i18n('Set as default values')}
            </Button>
          )}
        </>
      )}
    </Stack>
  );
};

export default DashboardVariablesBar;
