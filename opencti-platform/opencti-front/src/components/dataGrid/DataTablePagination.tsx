import Typography from '@mui/material/Typography';
import React, { type Dispatch, type SetStateAction, useCallback, useEffect, useState } from 'react';
import { ArrowLeft, ArrowRight } from '@mui/icons-material';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { ButtonGroup } from '@mui/material';
import Button from '@mui/material/Button';
import { PopoverProps } from '@mui/material/Popover/Popover';
import Menu from '@mui/material/Menu';
import { TableTuneIcon } from 'filigran-icon';
import { useFormatter } from '../i18n';
import { DataTableVariant, LocalStorageColumns } from './dataTableTypes';
import { NumberOfElements, usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import { useDataTableContext } from './dataTableUtils';

const DataTablePagination = ({
  page,
  setPage,
  numberOfElements: unstoreNOE,
}: {
  page: number,
  setPage: Dispatch<SetStateAction<number>>,
  numberOfElements?: NumberOfElements,
}) => {
  const { t_i18n } = useFormatter();

  const {
    storageKey,
    initialValues,
    variant,
    resetColumns,
    useDataTableLocalStorage,
  } = useDataTableContext();

  const {
    viewStorage: { pageSize, numberOfElements: storedNOE = { original: 0, number: 0, symbol: '' } },
    helpers,
  } = usePaginationLocalStorage(storageKey, initialValues, variant !== DataTableVariant.default);
  const numberOfElements = unstoreNOE ?? storedNOE;

  // if the number of elements object changes, it means we have changed the filter or search
  // we reset to page 1 (we might be out-of-bound in this new context)
  useEffect(() => {
    setPage(1);
  }, [numberOfElements]);

  const items = pageSize ? Number.parseInt(pageSize, 10) : 25;
  const firstItem = items * ((page ?? 1) - 1) + 1;
  const lastItem = Math.min(firstItem + items - 1, numberOfElements.original ?? 0);

  const fetchMore = useCallback((direction = 'forward') => {
    let nextPage;
    if (direction === 'previous' && page > 1) {
      nextPage = page - 1;
      setPage(nextPage);
    } else {
      nextPage = page + 1;
      setPage(nextPage);
    }
  }, [page, pageSize]);

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [_, setLocalStorageColumns] = useDataTableLocalStorage<LocalStorageColumns>(`${storageKey}_columns`, {}, true, true);

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        marginBottom: 10,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
        }}
      >
        <Typography sx={{ marginRight: 1 }} variant={'body2'}>{t_i18n('Rows per page:')}</Typography>
        <Select
          value={pageSize ?? '25'}
          size="small"
          variant="standard"
          sx={{ fontSize: 'small', marginRight: 1 }}
          onChange={(event) => helpers.handleAddProperty('pageSize', event.target.value)}
        >
          <MenuItem key="10" value="10">10</MenuItem>
          <MenuItem key="25" value="25">25</MenuItem>
          <MenuItem key="50" value="50">50</MenuItem>
          <MenuItem key="100" value="100">100</MenuItem>
        </Select>
      </div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
        }}
      >
        <ButtonGroup
          size="small"
          variant="text"
          color="pagination"
        >
          <Button
            onClick={() => fetchMore('previous')}
            size="small"
            disabled={firstItem === 1}
            style={{
              paddingLeft: 0,
              paddingRight: 0,
              borderRight: 'none',
              minWidth: 24,
            }}
          >
            <ArrowLeft />
          </Button>
          <Button
            disabled
            sx={{
              ':disabled': {
                borderRight: '0 !important',
                color: 'pagination.main',
              },
            }}
          >
            <Typography variant="body2">
              <span>{`${lastItem ? firstItem : 0} - ${lastItem} `}</span>
              <span style={{ opacity: 0.6 }}>
                {`/ ${numberOfElements.number}${numberOfElements.symbol}`}
              </span>
            </Typography>
          </Button>
          <Button
            onClick={() => fetchMore('forward')}
            size="small"
            disabled={lastItem === numberOfElements.original}
            style={{ paddingLeft: 0, paddingRight: 0, minWidth: 24 }}
          >
            <ArrowRight />
          </Button>
        </ButtonGroup>
        <Button
          variant="outlined"
          size="small"
          color="pagination"
          style={{
            marginLeft: 15,
            padding: 4,
            minWidth: 32,
            height: 32,
          }}
          onClick={(e) => setAnchorEl(e.currentTarget)}
        >
          <TableTuneIcon />
        </Button>
      </div>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={() => setAnchorEl(null)}>
        <MenuItem
          onClick={() => {
            setLocalStorageColumns({});
            resetColumns();
            setAnchorEl(null);
          }}
        >
          {t_i18n('Reset table')}
        </MenuItem>
      </Menu>
    </div>
  );
};

export default DataTablePagination;
