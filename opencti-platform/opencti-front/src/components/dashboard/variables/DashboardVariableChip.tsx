import { useState, type MouseEvent } from 'react';
import Popover from '@mui/material/Popover';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Button from '@common/button/Button';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { DeleteOutlined, EditOutlined } from '@mui/icons-material';
import { useFormatter } from '../../i18n';
import type { DashboardVariable } from '../dashboard-types';
import DashboardVariableValueInput from './DashboardVariableValueInput';
import useVariableValueLabels, { type VariableValueLabels } from './useVariableValueLabels';

// FDS-WORKAROUND #69: the library Chip has no muted (still clickable) state, `disabled` would block the click.
const UNUSED_OPACITY = 0.6;

export interface DashboardVariableChipProps {
  variable: DashboardVariable;
  // Effective value (undefined when the variable has neither a value nor a default).
  value: string | undefined;
  usedInWidgetIds: readonly string[];
  // The labels of the current value, when the bar already resolved those of all its chips at once.
  // The chip resolves its own value when it is not provided.
  valueLabels?: VariableValueLabels;
  // The value cannot be edited for now (the values are being saved): the chip is inert and shows it.
  disabled?: boolean;
  onChange: (value: string) => void;
  // The actions of the popover footer only exist when their callback is provided.
  onEdit?: (variable: DashboardVariable) => void;
  onDelete?: (variable: DashboardVariable) => void;
}

const inputKey = (variable: DashboardVariable) => [
  variable.type,
  'entityTypes' in variable ? variable.entityTypes.join() : '',
  'vocabularyCategory' in variable ? variable.vocabularyCategory : '',
  'killChainName' in variable ? variable.killChainName : '',
].join('|');

const DashboardVariableChip = ({ variable, value, usedInWidgetIds, valueLabels, disabled = false, onChange, onEdit, onDelete }: DashboardVariableChipProps) => {
  const { t_i18n, fsd } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  // Nothing to resolve (so no query) when the bar already did.
  const ownLabels = useVariableValueLabels(variable, valueLabels || !value ? [] : [value]);
  const { labels, restricted } = valueLabels ?? ownLabels;
  const isUnused = usedInWidgetIds.length === 0;
  const hasActions = onEdit !== undefined || onDelete !== undefined;

  // No entry yet means the id is still resolving: the chip stays neutral until the label is known.
  // A date is stored as an ISO string: show it as the platform shows any other date.
  const valueLabel = value
    ? (variable.type === 'date' ? fsd(value) : labels.get(value) ?? '…')
    : t_i18n('Not set');
  // Decided by the resolution, not by the label: an entity can really be named `Restricted`.
  const isRestricted = value !== undefined && restricted.has(value);

  // The popover closes before the page opens its own dialog.
  const handleAction = (action: (variable: DashboardVariable) => void) => {
    setAnchorEl(null);
    action(variable);
  };

  const chip = (
    <Chip
      label={`${variable.name} : ${valueLabel}`}
      severity={isRestricted ? 'critical' : 'neutral'}
      disabled={disabled}
      onClick={(event: MouseEvent<HTMLElement>) => setAnchorEl(event.currentTarget)}
    />
  );

  return (
    <Stack
      direction="row"
      alignItems="center"
      data-testid={`dashboard-variable-chip-${variable.name}`}
      data-unused={isUnused}
      style={isUnused ? { opacity: UNUSED_OPACITY } : undefined}
    >
      {isUnused ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span>{chip}</span>
          </TooltipTrigger>
          <TooltipContent>{t_i18n('Not used by any widget')}</TooltipContent>
        </Tooltip>
      ) : chip}
      <Popover
        open={anchorEl !== null && !disabled}
        anchorEl={anchorEl}
        onClose={() => setAnchorEl(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      >
        <Box sx={{ padding: 2, minWidth: 280 }}>
          <DashboardVariableValueInput
            key={inputKey(variable)}
            variable={variable}
            value={value ?? ''}
            onChange={onChange}
            commitOn="blur"
          />
          {hasActions && (
            <Stack direction="row" justifyContent="flex-end" gap={1} sx={{ marginTop: 2 }}>
              {onEdit && (
                <Button
                  variant="secondary"
                  size="small"
                  data-testid="dashboard-variable-edit"
                  startIcon={<EditOutlined />}
                  onClick={() => handleAction(onEdit)}
                >
                  {t_i18n('Edit variable')}
                </Button>
              )}
              {onDelete && (
                <Button
                  intent="destructive"
                  size="small"
                  data-testid="dashboard-variable-delete"
                  startIcon={<DeleteOutlined />}
                  onClick={() => handleAction(onDelete)}
                >
                  {t_i18n('Delete variable')}
                </Button>
              )}
            </Stack>
          )}
        </Box>
      </Popover>
    </Stack>
  );
};

export default DashboardVariableChip;
