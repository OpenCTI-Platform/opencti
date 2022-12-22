import React from 'react';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { BiotechOutlined } from '@mui/icons-material';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import * as R from 'ramda';
import Chip from '@mui/material/Chip';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';

const useStyles = makeStyles((theme) => ({
  filtersDialog: {
    margin: '0 0 20px 0',
  },
  filter: {
    margin: '0 10px 10px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.paper,
    margin: '0 10px 10px 0',
  },
}));

const DialogFilters = ({
  handleOpenFilters,
  disabled,
  size,
  fontSize,
  open,
  filters,
  handleCloseFilters,
  handleRemoveFilter,
  handleSearch,
  filterElement,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  return (
    <React.Fragment>
      <Tooltip title={t('Advanced search')}>
        <IconButton
          onClick={handleOpenFilters}
          disabled={disabled}
          size={size || 'medium'}
        >
          <BiotechOutlined fontSize={fontSize || 'medium'} />
        </IconButton>
      </Tooltip>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={open}
        onClose={handleCloseFilters}
        fullWidth={true}
        maxWidth="md"
      >
        <DialogTitle>{t('Advanced search')}</DialogTitle>
        <DialogContent style={{ paddingTop: 10 }}>
          {!R.isEmpty(filters) && (
            <div className={classes.filtersDialog}>
              {R.map((currentFilter) => {
                const label = `${truncate(
                  t(`filter_${currentFilter[0]}`),
                  20,
                )}`;
                const localFilterMode = currentFilter[0].endsWith('not_eq') ? t('AND') : t('OR');
                const values = (
                  <span>
                      {R.map(
                        (n) => (
                          <span key={n.value}>
                            {truncate(n.value, 15)}{' '}
                            {R.last(currentFilter[1]).value !== n.value && (
                              <code style={{ marginRight: 5 }}>{localFilterMode}</code>
                            )}
                          </span>
                        ),
                        currentFilter[1],
                      )}
                    </span>
                );
                return (
                  <span key={currentFilter[0]}>
                      <Chip
                        classes={{ root: classes.filter }}
                        label={
                          <div>
                            <strong>{label}</strong>: {values}
                          </div>
                        }
                        onDelete={() => handleRemoveFilter(currentFilter[0])}
                      />
                    {R.last(R.toPairs(filters))[0] !== currentFilter[0] && (
                      <Chip
                        classes={{ root: classes.operator }}
                        label={t('AND')}
                      />
                    )}
                    </span>
                );
              }, R.toPairs(filters))}
            </div>
          )}
          {filterElement}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseFilters}>
            {t('Cancel')}
          </Button>
          <Button color="secondary" onClick={handleSearch}>
            {t('Search')}
          </Button>
        </DialogActions>
      </Dialog>
    </React.Fragment>
  );
};

export default DialogFilters;
