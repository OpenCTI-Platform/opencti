import { FunctionComponent, useState } from 'react';
import { IconButton, Tooltip } from '@mui/material';
import { Add } from '@mui/icons-material';
import { Disposable, graphql } from 'relay-runtime';
import Box from '@mui/material/Box';
import { ThemeManagerQuery, ThemeManagerQuery$variables } from '@components/settings/themes/__generated__/ThemeManagerQuery.graphql';
import { ThemeManager_lines_data$data } from '@components/settings/themes/__generated__/ThemeManager_lines_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import DataTable from '../../../../components/dataGrid/DataTable';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ThemePopover from './ThemePopover';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import ThemeCreation from './ThemeCreation';
import ThemeImporter from './ThemeImporter';
import Card from '../../../../components/common/card/Card';

const LOCAL_STORAGE_KEY = 'themes';

export const refetchableThemesQuery = graphql`
  fragment ThemeManager_themes on Query
  @refetchable(queryName: "ThemeManagerThemesRefetchQuery") {
    themes(orderBy: created_at, orderMode: desc) {
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
    $orderBy: ThemeOrdering
    $orderMode: OrderingMode
  ) {
    ...ThemeManager_lines_data @arguments(
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

const themesLinesFragment = graphql`
  fragment ThemeManager_lines_data on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ThemeOrdering" }
    orderMode: { type: "OrderingMode" }

  )
  @refetchable(queryName: "ThemeManagerLinesRefetchQuery") {
    themes(
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
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
    built_in
  }
`;

interface ThemeManagerProps {
  handleRefetch: () => Disposable;
  defaultTheme?: {
    id: string;
    name: string;
  } | null;
}

const ThemeManager: FunctionComponent<ThemeManagerProps> = ({
  handleRefetch,
  defaultTheme,
}) => {
  const { t_i18n } = useFormatter();
  const [displayCreation, setDisplayCreation] = useState<boolean>(false);

  const initialValues = {
    sortBy: 'created_at',
    orderAsc: false,
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
      percentWidth: 100,
      isSortable: false,
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
      <Card
        title={t_i18n('Themes')}
        sx={{ flex: '0 auto' }}
        action={(
          <Box>
            <Tooltip title={t_i18n('Create a custom theme')}>
              <IconButton
                color="primary"
                aria-label={t_i18n('Create a custom theme')}
                onClick={handleOpenCreation}
                size="small"
                data-testid="create-theme-btn"
              >
                <Add fontSize="small" />
              </IconButton>
            </Tooltip>

            <ThemeImporter
              handleRefetch={handleRefetch}
              paginationOptions={queryPaginationOptions}
            />
          </Box>
        )}
      >
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            disableLineSelection
            disableNavigation
            hideSearch
            hideFilters
            variant={DataTableVariant.inline}
            actions={(row) => {
              return (
                <ThemePopover
                  themeData={row}
                  handleRefetch={handleRefetch}
                  paginationOptions={queryPaginationOptions}
                  canDelete={row.id !== defaultTheme?.id}
                  defaultTheme={defaultTheme}
                />
              );
            }}
            resolvePath={resolveThemesData}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            lineFragment={themesLineFragment}
            preloadedPaginationProps={preloadedPaginationOptions}

          />
        )}
      </Card>

      <ThemeCreation
        open={displayCreation}
        handleClose={handleCloseCreation}
        handleRefetch={handleRefetch}
        paginationOptions={queryPaginationOptions}
      />
    </>
  );
};

export default ThemeManager;
