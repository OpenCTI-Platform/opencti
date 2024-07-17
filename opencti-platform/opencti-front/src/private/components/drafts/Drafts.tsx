import React from 'react';
import DraftsLines, { draftsLinesQuery } from '@components/drafts/DraftsLines';
import { DraftLineDummy } from '@components/drafts/DraftLine';
import { DraftsLinesPaginationQuery, DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import DraftCreation from '@components/drafts/DraftCreation';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../components/i18n';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { DataColumns } from '../../../components/list_lines';
import ListLines from '../../../components/list_lines/ListLines';
import Breadcrumbs from '../../../components/Breadcrumbs';
import ExportContextProvider from '../../../utils/ExportContextProvider';

const LOCAL_STORAGE_KEY = 'draftWorkspaces';

const Drafts: React.FC = () => {
  const { t_i18n } = useFormatter();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<DraftsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: false,
      openExports: false,
      filters: emptyFilterGroup,
    },
  );
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
  } = viewStorage;

  const queryRef = useQueryLoading<DraftsLinesPaginationQuery>(
    draftsLinesQuery,
    paginationOptions,
  );

  const renderLines = () => {
    const dataColumns: DataColumns = {
      name: {
        label: 'Name',
        width: '100%',
        isSortable: true,
      },
    };

    return (
      <div data-testid="draft-page">
        <ListLines
          helpers={storageHelpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={storageHelpers.handleSearch}
          handleAddFilter={storageHelpers.handleAddFilter}
          handleRemoveFilter={storageHelpers.handleRemoveFilter}
          handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
          handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
          keyword={searchTerm}
          filters={filters}
          noPadding={true}
          iconExtension={false}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          secondaryAction={true}
          entityTypes={['DraftWorkspace']}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <DraftLineDummy
                        key={idx}
                        dataColumns={dataColumns}
                      />
                    ))}
                </>
              }
            >
              <DraftsLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
              />
            </React.Suspense>
          )}
        </ListLines>
      </div>
    );
  };
  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Drafts'), current: true }]} />
      {renderLines()}
      {<DraftCreation paginationOptions={paginationOptions} />}
    </ExportContextProvider>
  );
};

export default Drafts;
