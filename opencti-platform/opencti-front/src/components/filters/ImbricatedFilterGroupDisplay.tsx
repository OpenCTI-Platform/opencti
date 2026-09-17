import React, { CSSProperties, FunctionComponent, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import { InformationOutline } from 'mdi-material-ui';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material';
import CodeBlock from '@components/common/CodeBlock';
import Typography from '@mui/material/Typography';
import { Chip } from '@filigran/design-system';
import { useFormatter } from '../i18n';
import { FilterRepresentative } from './FiltersModel';
import type { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import FilterGroupsVisualDisplay from './FilterGroupsVisualDisplay';
import { SURFACE_LAYER, fdsLayerClass, layerInputVars } from '../../utils/fdsLayer';

interface ImbricatedFilterGroupDisplayProps {
  filterObj: FilterGroup;
  filterMode: string;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  filterStyle?: CSSProperties;
}

const ImbricatedFilterGroupDisplay: FunctionComponent<ImbricatedFilterGroupDisplayProps> = ({
  filterObj,
  filterMode,
  filtersRepresentativesMap,
  filterStyle,
}) => {
  const { filterGroups } = filterObj;
  const [open, setOpen] = useState(false);
  const { t_i18n } = useFormatter();
  const theme = useTheme();

  const handleClickOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  return (
    <>
      <Chip
        severity="info"
        startIcon={<InformationOutline fontSize="small" />}
        label={t_i18n('Filters are not fully displayed')}
        onClick={handleClickOpen}
        style={filterStyle}
      />

      <Dialog
        // A dialog is a layer-2 surface, like a drawer. See utils/fdsLayer.ts.
        slotProps={{ paper: { className: fdsLayerClass(SURFACE_LAYER), sx: { ...layerInputVars } } }}
        open={open}
        onClose={handleClose}
        maxWidth={false}
        aria-labelledby="filter-groups-dialog-title"
        aria-describedby="Show Filter groups configuration"
      >
        <DialogTitle id="filter-groups-dialog-title">
          {t_i18n('Imbricated filter groups')}
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
            <Typography
              variant="body2"
              sx={{ marginBottom: theme.spacing(2), width: '100%', contain: 'inline-size' }}
            >
              {t_i18n('This filter group contains nested filter groups. The full content is displayed below for reference. It can be edited via the API or directly from the filters line on the entity page.')}
            </Typography>
            <Typography
              variant="h3"
              sx={{ textTransform: 'none' }}
              gutterBottom
            >
              {t_i18n('Full filter group content:')}
            </Typography>
            <Box
              sx={{ width: '100%' }}
            >
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
            <Box
              sx={{ width: '100%', overflowX: 'auto', contain: 'inline-size' }}
            >
              <CodeBlock
                code={JSON.stringify(filterObj, null, 2)}
                language="json"
              />
            </Box>
          </Box>
        </DialogContent>
        <DialogActions sx={{ mr: 2, mb: 2 }}>
          <Button onClick={handleClose} autoFocus>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ImbricatedFilterGroupDisplay;
