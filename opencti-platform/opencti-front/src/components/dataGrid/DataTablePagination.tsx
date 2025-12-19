import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import React, { type Dispatch, type SetStateAction, Suspense, useCallback, useEffect } from 'react';
import { ArrowLeft, ArrowRight } from '@mui/icons-material';
import { ButtonGroup } from '@mui/material';
import IconButton from '@common/button/IconButton';
import { TableTuneIcon } from 'filigran-icon';
import { useFormatter } from '../i18n';
import { NumberOfElements } from '../../utils/hooks/useLocalStorage';
import NestedMenuButton from '../nested_menu/NestedMenuButton';
import { useDataTableContext } from './components/DataTableContext';

const DataTablePagination = ({
  page,
  setPage,
  numberOfElements: unstoreNOE,
  redirectionModeEnabled = false,
}: {
  page: number;
  setPage: Dispatch<SetStateAction<number>>;
  numberOfElements?: NumberOfElements;
  redirectionModeEnabled?: boolean;
}) => {
  const { t_i18n } = useFormatter();

  const {
    resetColumns,
    useDataTablePaginationLocalStorage: {
      viewStorage: {
        pageSize,
        numberOfElements: storedNOE = { original: 0, number: 0, symbol: '' },
        redirectionMode,
      },
      helpers,
    },
  } = useDataTableContext();

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

  const resetTable = () => {
    resetColumns();
    helpers.handleAddProperty('pageSize', '25');
  };
  const nestedMenuOptions = [
    {
      value: 'menu-reset',
      label: t_i18n('Reset table'),
      onClick: () => resetTable(),
      menuLevel: 0,
    },
    {
      value: 'menu-rows-per-page',
      label: t_i18n('Rows per page'),
      menuLevel: 0,
      nestedOptions: [
        {
          value: '10',
          onClick: () => helpers.handleAddProperty('pageSize', '10'),
          selected: pageSize === '10',
          menuLevel: 1,
        },
        {
          value: '25',
          onClick: () => helpers.handleAddProperty('pageSize', '25'),
          selected: !pageSize || pageSize === '25',
          menuLevel: 1,
        },
        {
          value: '50',
          onClick: () => helpers.handleAddProperty('pageSize', '50'),
          selected: pageSize === '50',
          menuLevel: 1,
        },
        {
          value: '100',
          onClick: () => helpers.handleAddProperty('pageSize', '100'),
          selected: pageSize === '100',
          menuLevel: 1,
        },
      ],
    },
    ...(redirectionModeEnabled
      ? [
          {
            label: t_i18n('Redirection mode'),
            menuLevel: 0,
            value: 'redirect-mode',
            nestedOptions: [
              {
                label: t_i18n('Redirecting to the Overview section'),
                value: 'overview',
                menuLevel: 1,
                onClick: () => helpers.handleAddProperty('redirectionMode', 'overview'),
                selected: redirectionMode === 'overview',
              },
              {
                label: t_i18n('Redirecting to the Knowledge section'),
                value: 'knowledge',
                menuLevel: 1,
                onClick: () => helpers.handleAddProperty('redirectionMode', 'knowledge'),
                selected: redirectionMode === 'knowledge',
              },
              {
                label: t_i18n('Redirecting to the Content section'),
                value: 'content',
                menuLevel: 1,
                onClick: () => helpers.handleAddProperty('redirectionMode', 'content'),
                selected: redirectionMode === 'content',
              },
            ],
          },
        ]
      : []),
  ];

  return (
    <Box
      sx={{
        display: 'flex',
        borderRadius: 1,
        border: 1,
        borderColor: 'divider',
      }}
    >
      <ButtonGroup
        size="small"
        variant="text"
        color="pagination"
      >
        <IconButton
          onClick={() => fetchMore('previous')}
          variant="tertiary"
          size="default"
          disabled={firstItem === 1}
          style={{
            padding: 0,
            borderRight: 'none',
            minWidth: 24,
          }}
        >
          <ArrowLeft />
        </IconButton>
        <Tooltip
          title={(
            <div>
              <strong>{`${numberOfElements.original}`}</strong>{' '}
              {t_i18n('entitie(s)')}
            </div>
          )}
        >
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              borderRight: '0 !important',
              color: 'pagination.main',
            }}
          >
            <Typography variant="body2">
              <span>{`${lastItem ? firstItem : 0} - ${lastItem} `}</span>
              <span style={{ opacity: 0.6 }}>
                {`/ ${numberOfElements.number}${numberOfElements.symbol}`}
              </span>
            </Typography>
          </Box>
        </Tooltip>
        <IconButton
          onClick={() => fetchMore('forward')}
          variant="tertiary"
          size="default"
          disabled={lastItem === numberOfElements.original}
          style={{ paddingLeft: 0, paddingRight: 0, minWidth: 24 }}
        >
          <ArrowRight />
        </IconButton>
      </ButtonGroup>
      <Suspense>
        <NestedMenuButton
          menuButtonProps={{
            variant: 'outlined',
            size: 'small',
            color: 'primary',
            style: {
              padding: 6,
              minWidth: 36,
              border: 'none',
            },
          }}
          menuButtonChildren={<TableTuneIcon />}
          options={nestedMenuOptions}
          menuLevels={2}
        />
      </Suspense>
    </Box>
  );
};

export default DataTablePagination;
