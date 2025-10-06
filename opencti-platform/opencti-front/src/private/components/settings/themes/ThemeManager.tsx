import React, { FunctionComponent, useRef, useState } from 'react';
import { IconButton, Paper, Stack, Tooltip, Typography } from '@mui/material';
import { Add } from '@mui/icons-material';
import { Disposable, graphql } from 'relay-runtime';
import Box from '@mui/material/Box';
import { ThemeManagerQuery, ThemeManagerQuery$variables } from '@components/settings/themes/__generated__/ThemeManagerQuery.graphql';
import { ThemeManager_data$data } from '@components/settings/themes/__generated__/ThemeManager_data.graphql';
import { ThemeManager_lines_data$data } from '@components/settings/themes/__generated__/ThemeManager_lines_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import DataTable from '../../../../components/dataGrid/DataTable';
import { emptyFilterGroup, useGetDefaultFilterObject } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ThemePopover from './ThemePopover';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import ThemeCreation from './ThemeCreation';
import ThemeImporter from './ThemeImporter';

const LOCAL_STORAGE_KEY = 'themes';

export const refetchableThemesQuery = graphql`
  fragment ThemeManager_themes on Query
  @refetchable(queryName: "ThemeManagerThemesRefetchQuery") {
    themes {
      edges {
        node {
          id
          name
          theme_background
          theme_paper
          theme_nav
          theme_primary
          theme_secondary
          theme_accent
          theme_text_color
          theme_logo
          theme_logo_collapsed
          theme_logo_login
        }
      }
    }
  }
`;

const themeManagerQuery = graphql`
  query ThemeManagerQuery(
    $count: Int!
    $cursor: ID
  ) {
    ...ThemeManager_lines_data
    @arguments(
      count: $count
      cursor: $cursor
    )
  }
`;

const themesLinesFragment = graphql`
  fragment ThemeManager_lines_data on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  )
  @refetchable(queryName: "ThemeManagerLinesRefetchQuery") {
    themes(
      first: $count
      after: $cursor
    ) @connection(key: "Pagination_themes") {
      edges {
        node {
          ...ThemeManager_data
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

const themesLineFragment = graphql`
  fragment ThemeManager_data on Theme {
    id
    name
    theme_background
    theme_paper
    theme_nav
    theme_primary
    theme_secondary
    theme_accent
    theme_logo
    theme_logo_collapsed
    theme_logo_login
    theme_text_color
    system_default
  }
`;

interface ThemeManagerProps {
  handleRefetch: () => Disposable;
  currentTheme: string;
}

const ThemeManager: FunctionComponent<ThemeManagerProps> = ({
  handleRefetch,
  currentTheme,
}) => {
  const { t_i18n } = useFormatter();
  const [displayCreation, setDisplayCreation] = useState<boolean>(false);
  const ref = useRef(null);

  const initialValues = {
    sortBy: 'name',
    orderAsc: false,
    openExports: false,
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['entity_type'], ['Stix-Core-Object']),
    },
  };

  const { helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<ThemeManagerQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const queryPaginationOptions = {
    ...paginationOptions,
  } as unknown as ThemeManagerQuery$variables;

  const queryRef = useQueryLoading<ThemeManagerQuery>(
    themeManagerQuery,
    queryPaginationOptions,
  );

  const dataColumns = {
    name: {
      id: '',
      label: t_i18n('Name'),
      percentWidth: 100,
      isSortable: false,
      render: (node: { id: string; name: string }) => node.name,
    },
  };

  const preloadedPaginationOptions = {
    linesQuery: themeManagerQuery,
    linesFragment: themesLinesFragment,
    queryRef,
    nodePath: ['themes', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ThemeManagerQuery>;

  const handleOpenCreation = () => setDisplayCreation(true);
  const handleCloseCreation = () => setDisplayCreation(false);

  const resolveThemesData = (data: ThemeManager_lines_data$data) => data.themes?.edges?.map((n) => n?.node);

  return (
    <>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Typography variant="h4" gutterBottom>{t_i18n('Themes')}</Typography>

        <Box>
          <Tooltip title={t_i18n('Add')}>
            <IconButton
              color="primary"
              aria-label={t_i18n('Add')}
              onClick={handleOpenCreation}
              size="large"
              data-testid="create-theme-btn"
            >
              <Add fontSize="small" />
            </IconButton>
          </Tooltip>

          <ThemeImporter
            handleRefetch={handleRefetch}
            paginationOptions={paginationOptions.variables}
          />
        </Box>
      </Stack>

      <Paper
        ref={ref}
        variant="outlined"
        style={{ padding: '0 15px 15px' }}
      >
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            disableLineSelection
            disableNavigation
            hideSearch
            hideFilters
            variant={DataTableVariant.inline}
            actions={(row) => (
              <ThemePopover
                themeData={row}
                handleRefetch={handleRefetch}
                paginationOptions={paginationOptions.variables}
                isCurrentTheme={row.id === currentTheme}
              />
            )}
            resolvePath={resolveThemesData}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            lineFragment={themesLineFragment}
            preloadedPaginationProps={preloadedPaginationOptions}
          />
        )}
      </Paper>

      <ThemeCreation
        open={displayCreation}
        handleClose={handleCloseCreation}
        handleRefetch={handleRefetch}
        paginationOptions={paginationOptions.variables}
      />
    </>
  );
};

export default ThemeManager;
