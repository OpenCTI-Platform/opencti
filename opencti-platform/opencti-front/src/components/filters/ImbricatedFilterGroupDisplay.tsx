import React, { CSSProperties, FunctionComponent, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import { InformationOutline } from 'mdi-material-ui';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import { useTheme } from '@mui/material';
import CodeBlock from '@components/common/CodeBlock';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import { useFormatter } from '../i18n';
import { FilterRepresentative } from './FiltersModel';
import type { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import FilterGroupsVisualDisplay from './FilterGroupsVisualDisplay';

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
        style={filterStyle}
        sx={{
          '& .MuiChip-label': {
            lineHeight: '32px',
            maxWidth: 400,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            display: 'flex',
            alignItems: 'center',
            gap: 0.5,
          },
        }}
        color="warning"
        onClick={handleClickOpen}
        label={(
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, textTransform: 'none' }}>
            {t_i18n('Filters are not fully displayed')}
            <InformationOutline
              fontSize="small"
              color="secondary"
            />
          </span>
        )}
      />

      <Dialog
        open={open}
        onClose={handleClose}
        aria-labelledby="filter-groups-dialog-title"
        aria-describedby="Show Filter groups configuration"
      >
        <DialogTitle id="filter-groups-dialog-title">
          {t_i18n('Imbricated filter groups')}
        </DialogTitle>
        <DialogContent>
          <Typography
            variant="body2"
            sx={{ marginBottom: theme.spacing(2) }}
          >
            {t_i18n('This filter contains imbricated filter groups, that are not fully supported yet in the platform display and can only be edited via the API. They might have been created via the API or a migration from a previous filter format. For your information, here is information about the content of the filter object.')}
          </Typography>
          <Typography
            variant="h3"
            sx={{ textTransform: 'none' }}
            gutterBottom
          >
            {t_i18n('Your filter group cannot be modified yet:')}
          </Typography>
          <FilterGroupsVisualDisplay
            filtersRepresentativesMap={filtersRepresentativesMap}
            filterGroups={filterGroups}
            filterMode={filterMode}
          />
          <Typography
            variant="h3"
            sx={{ textTransform: 'none' }}
            gutterBottom
          >
            {t_i18n('The complete Filter object is as follows:')}
          </Typography>
          <CodeBlock
            code={JSON.stringify(filterObj, null, 2)}
            language="json"
          />
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
