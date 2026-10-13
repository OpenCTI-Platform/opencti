import { useState, type MouseEvent } from 'react';
import Popover from '@mui/material/Popover';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import { Chip, IconButton, Menu, MenuContent, MenuItem, MenuTrigger, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { DeleteOutlined, EditOutlined, MoreVert } from '@mui/icons-material';
import { useFormatter } from '../../i18n';
import { EXPORT_REMOVE_CLASS } from '../../../utils/Image';
import type { DashboardVariable } from '../dashboard-types';
import DashboardVariableValueInput from './DashboardVariableValueInput';
import useVariableValueLabels from './useVariableValueLabels';
import { isIdVariableType } from './variableTypeSearch';

// FDS-WORKAROUND: the library Chip has no muted (still clickable) state, `disabled` would block the click.
const UNUSED_OPACITY = 0.6;

export interface DashboardVariableChipProps {
  variable: DashboardVariable;
  // Effective value (undefined when the variable has neither a value nor a default).
  value: string | undefined;
  usedInWidgetIds: readonly string[];
  onChange: (value: string) => void;
  // The menu entries only exist when their callback is provided.
  onEdit?: (variable: DashboardVariable) => void;
  onDelete?: (variable: DashboardVariable) => void;
}

const inputKey = (variable: DashboardVariable) => [
  variable.type,
  'entityTypes' in variable ? variable.entityTypes.join() : '',
  'vocabularyCategory' in variable ? variable.vocabularyCategory : '',
  'killChainName' in variable ? variable.killChainName : '',
].join('|');

const DashboardVariableChip = ({ variable, value, usedInWidgetIds, onChange, onEdit, onDelete }: DashboardVariableChipProps) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const labels = useVariableValueLabels(variable, value ? [value] : []);
  const isUnused = usedInWidgetIds.length === 0;
  const hasMenu = onEdit !== undefined || onDelete !== undefined;

  // No entry yet means the id is still resolving: the chip stays neutral until the label is known.
  const valueLabel = value ? labels.get(value) ?? '…' : t_i18n('Not set');
  const isRestricted = isIdVariableType(variable.type) && valueLabel === t_i18n('Restricted');

  const chip = (
    <Chip
      label={`${variable.name} : ${valueLabel}`}
      severity={isRestricted ? 'critical' : 'neutral'}
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
      {hasMenu && (
        <Menu open={menuOpen} onOpenChange={setMenuOpen}>
          <MenuTrigger asChild>
            <IconButton
              className={EXPORT_REMOVE_CLASS}
              variant="default"
              priority="tertiary"
              aria-label={`${t_i18n('Open menu')}: ${variable.name}`}
              active={menuOpen}
              icon={<MoreVert />}
            />
          </MenuTrigger>
          <MenuContent align="end">
            {onEdit && (
              <MenuItem startIcon={<EditOutlined fontSize="small" />} onSelect={() => onEdit(variable)}>
                {t_i18n('Edit variable')}
              </MenuItem>
            )}
            {onDelete && (
              <MenuItem startIcon={<DeleteOutlined fontSize="small" />} onSelect={() => onDelete(variable)}>
                {t_i18n('Delete variable')}
              </MenuItem>
            )}
          </MenuContent>
        </Menu>
      )}
      <Popover
        open={anchorEl !== null}
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
          />
        </Box>
      </Popover>
    </Stack>
  );
};

export default DashboardVariableChip;
