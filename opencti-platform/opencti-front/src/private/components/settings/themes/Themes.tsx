import React, { FunctionComponent, useRef, useState } from 'react';
import { IconButton, Paper, Tooltip, Typography } from '@mui/material';
import { Add } from '@mui/icons-material';
import { Disposable, graphql } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import DataTable from '../../../../components/dataGrid/DataTable';
import { emptyFilterGroup, useGetDefaultFilterObject } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { ThemesLinesSearchQuery, ThemesLinesSearchQuery$variables } from './__generated__/ThemesLinesSearchQuery.graphql';
import { ThemesLines_data$data } from './__generated__/ThemesLines_data.graphql';
import ThemePopover from './ThemePopover';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import ThemeCreation from './ThemeCreation';
import ThemeImporter from './ThemeImporter';
import { deserializeThemeManifest } from './ThemeType';
import { ThemesLine_data$data } from './__generated__/ThemesLine_data.graphql';

const LOCAL_STORAGE_KEY = 'themes';

export const refetchableThemesQuery = graphql`
  fragment Themes_themes on Query
  @refetchable(queryName: "ThemesRefetchQuery") {
    themes {
      edges {
        node {
          id
          name
          manifest
        }
      }
    }
  }
`;

const themesLinesSearchQuery = graphql`
  query ThemesLinesSearchQuery(
    $count: Int!
    $cursor: ID
  ) {
    ...ThemesLines_data
    @arguments(
      count: $count
      cursor: $cursor
    )
  }
`;

const themesLinesFragment = graphql`
  fragment ThemesLines_data on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  )
  @refetchable(queryName: "ThemesLinesRefetchQuery") {
    themes(
      first: $count
      after: $cursor
    ) @connection(key: "Pagination_themes") {
      edges {
        node {
          ...ThemesLine_data
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
  fragment ThemesLine_data on Theme {
    id
    name
    manifest
  }
`;

interface ThemesProps {
  handleRefetch: () => Disposable;
}

const Themes: FunctionComponent<ThemesProps> = ({
  handleRefetch,
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
  const dataColumns = {
    name: {
      id: '',
      label: t_i18n('Name'),
      percentWidth: 100,
      isSortable: false,
      render: (node: ThemesLine_data$data) => (
        deserializeThemeManifest(node.manifest).system_default
          ? t_i18n(node.name)
          : node.name),
    },
  };
  const { helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<ThemesLinesSearchQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const queryPaginationOptions = {
    ...paginationOptions,
  } as unknown as ThemesLinesSearchQuery$variables;
  const queryRef = useQueryLoading<ThemesLinesSearchQuery>(
    themesLinesSearchQuery,
    queryPaginationOptions,
  );
  const preloadedPaginationOptions = {
    linesQuery: themesLinesSearchQuery,
    linesFragment: themesLinesFragment,
    queryRef,
    nodePath: ['themes', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ThemesLinesSearchQuery>;

  const handleOpenCreation = () => setDisplayCreation(true);
  const handleCloseCreation = () => setDisplayCreation(false);

  return (
    <>
      <div style={{ display: 'flex', marginBottom: -6 }}>
        <Typography variant="h4" gutterBottom>
          {t_i18n('Themes')}
        </Typography>
        <div style={{ marginTop: -15 }}>
          <Tooltip title={t_i18n('Add')}>
            <IconButton
              color="primary"
              aria-label={t_i18n('Add')}
              onClick={handleOpenCreation}
              size="large"
            >
              <Add fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title={t_i18n('Import a theme')}>
            <ThemeImporter
              handleRefetch={handleRefetch}
              paginationOptions={paginationOptions.variables}
            />
          </Tooltip>
        </div>
      </div>
      <div className="clearfix" />
      <Paper
        ref={ref}
        variant="outlined"
        style={{
          margin: 0,
          padding: '0 15px 15px',
          borderRadius: 4,
          position: 'relative',
          listStyleType: 'none',
        }}
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
              />
            )}
            resolvePath={(data: ThemesLines_data$data) => data.themes?.edges?.map((n) => n?.node)}
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

export default Themes;
