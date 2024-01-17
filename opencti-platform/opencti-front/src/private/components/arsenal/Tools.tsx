import React from 'react';
import { makeStyles } from '@mui/styles';
import ListLines from '../../../components/list_lines/ListLines';
import ToolsLines, { toolsLinesQuery } from './tools/ToolsLines';
import ToolCreation from './tools/ToolCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { ToolLineDummy } from './tools/ToolLine';
import { ToolsLinesPaginationQuery, ToolsLinesPaginationQuery$variables } from './tools/__generated__/ToolsLinesPaginationQuery.graphql';
import { buildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import BreadcrumbHeader from '../../../components/BreadcrumbHeader';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    paddingBottom: 25,
    color: theme.palette.mode === 'light'
      ? theme.palette.common.black
      : theme.palette.primary.main,
    fontSize: '24px',
    fontWeight: 'bold',
  },
}));

const LOCAL_STORAGE_KEY = 'tools';

const Tools = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ToolsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: emptyFilterGroup,
    },
  );

  const {
    sortBy,
    orderAsc,
    searchTerm,
    filters,
    openExports,
    numberOfElements,
  } = viewStorage;

  const contextFilters = buildEntityTypeBasedFilterContext('Tool', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ToolsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<ToolsLinesPaginationQuery>(
    toolsLinesQuery,
    queryPaginationOptions,
  );

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '35%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '25%',
        isSortable: false,
      },
      created: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        width: '15%',
        isSortable: true,
      },
    };

    return (
      <>
        <BreadcrumbHeader
          path={[
            { text: t_i18n('Arsenal') },
            { text: t_i18n('Tools') },
          ]}
        >
          <div className={ classes.header }>{t_i18n('Tools')}</div>
        </BreadcrumbHeader>
        <ListLines
          helpers={helpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={helpers.handleSort}
          handleSearch={helpers.handleSearch}
          handleAddFilter={helpers.handleAddFilter}
          handleRemoveFilter={helpers.handleRemoveFilter}
          handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
          handleSwitchLocalMode={helpers.handleSwitchLocalMode}
          handleToggleExports={helpers.handleToggleExports}
          openExports={openExports}
          exportContext={{ entity_type: 'Tool' }}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={queryPaginationOptions}
          numberOfElements={numberOfElements}
          availableFilterKeys={[
            'workflow_id',
            'objectLabel',
            'objectMarking',
            'createdBy',
            'source_reliability',
            'confidence',
            'created',
            'name',
          ]}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <ToolLineDummy
                        key={idx}
                        dataColumns={dataColumns}
                      />
                    ))}
                </>
              }
            >
              <ToolsLines
                queryRef={queryRef}
                paginationOptions={queryPaginationOptions}
                dataColumns={dataColumns}
                onLabelClick={helpers.handleAddFilter}
                setNumberOfElements={helpers.handleSetNumberOfElements}
              />
            </React.Suspense>
          )}
        </ListLines>
      </>
    );
  };
  return (
    <>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ToolCreation paginationOptions={queryPaginationOptions} />
      </Security>
    </>
  );
};

export default Tools;
