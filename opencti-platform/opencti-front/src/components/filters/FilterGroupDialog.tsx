import React, { FunctionComponent } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material';
import CodeBlock from '@components/common/CodeBlock';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../i18n';
import { FilterRepresentative } from './FiltersModel';
import type { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import FilterGroupsVisualDisplay from './FilterGroupsVisualDisplay';
import { SURFACE_LAYER, fdsLayerClass, layerInputVars } from '../../utils/fdsLayer';

export interface FilterGroupDialogProps {
  open: boolean;
  onClose: () => void;
  /** Groups shown by `FilterGroupsVisualDisplay` — the root's nested groups, or a single group wrapped in an array. */
  filterGroups: FilterGroup[];
  /** Separator shown between `filterGroups` when there is more than one. */
  filterMode: string;
  /** Raw object dumped in the JSON code block below the visual display. */
  jsonObject: unknown;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  title: string;
  /** Optional intro paragraph shown above the visual display. */
  description?: string;
}

/**
 * Read-only dialog showing the full content of one or more filter groups: the same
 * `FilterGroupsVisualDisplay` used for the "imbricated filter groups" notice, plus the raw JSON,
 * in a modal. Content only — open/close state, title and description are owned by the caller, so
 * it can be triggered either by `ImbricatedFilterGroupDisplay`'s own chip or by a read-only
 * filter-group chip that has no edit panel to open.
 */
const FilterGroupDialog: FunctionComponent<FilterGroupDialogProps> = ({
  open,
  onClose,
  filterGroups,
  filterMode,
  jsonObject,
  filtersRepresentativesMap,
  title,
  description,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();

  return (
    <Dialog
      // A dialog is a layer-2 surface, like a drawer. See utils/fdsLayer.ts.
      slotProps={{ paper: { className: fdsLayerClass(SURFACE_LAYER), sx: { ...layerInputVars } } }}
      open={open}
      onClose={onClose}
      maxWidth={false}
      aria-labelledby="filter-groups-dialog-title"
      aria-describedby="Show Filter groups configuration"
    >
      <DialogTitle id="filter-groups-dialog-title">
        {title}
      </DialogTitle>
      <DialogContent>
        <Box
          sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-start',
            minWidth: theme.breakpoints.values.sm,
          }}
        >
          {description && (
            <Typography
              variant="body2"
              sx={{ marginBottom: theme.spacing(2), width: '100%', contain: 'inline-size' }}
            >
              {description}
            </Typography>
          )}
          <Typography
            variant="h3"
            sx={{ textTransform: 'none' }}
            gutterBottom
          >
            {t_i18n('Full filter group content:')}
          </Typography>
          <Box sx={{ width: '100%' }}>
            <FilterGroupsVisualDisplay
              filtersRepresentativesMap={filtersRepresentativesMap}
              filterGroups={filterGroups}
              filterMode={filterMode}
            />
          </Box>
          <Typography
            variant="h3"
            sx={{ textTransform: 'none' }}
            gutterBottom
          >
            {t_i18n('The complete Filter object is as follows:')}
          </Typography>
          <Box sx={{ width: '100%', overflowX: 'auto', contain: 'inline-size' }}>
            <CodeBlock
              code={JSON.stringify(jsonObject, null, 2)}
              language="json"
            />
          </Box>
        </Box>
      </DialogContent>
      <DialogActions sx={{ mr: 2, mb: 2 }}>
        <Button onClick={onClose} autoFocus>
          {t_i18n('Close')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default FilterGroupDialog;
