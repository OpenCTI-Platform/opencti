import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import ListLines from '../../../components/list_lines/ListLines';
import ExternalReferencesLines, { externalReferencesLinesQuery } from './external_references/ExternalReferencesLines';
import ExternalReferenceCreation from './external_references/ExternalReferenceCreation';
import Security from '../../../utils/Security';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import {
  ExternalReferencesLinesPaginationQuery,
  ExternalReferencesLinesPaginationQuery$variables,
} from './external_references/__generated__/ExternalReferencesLinesPaginationQuery.graphql';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { ExternalReferenceLine_node$data } from './external_references/__generated__/ExternalReferenceLine_node.graphql';
import ToolBar from '../data/ToolBar';
import { ExternalReferenceLineDummy } from './external_references/ExternalReferenceLine';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useDynamicHeader from '../../../utils/hooks/useDynamicHeader';

const LOCAL_STORAGE_KEY = 'externalReferences';

interface ExternalReferencesProps {
  history: History;
  location: Location;
}

const ExternalReferences: FunctionComponent<ExternalReferencesProps> = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useDynamicHeader();
  setTitle(t_i18n('OpenCTI - Analyses: External References'));
  const { isFeatureEnable } = useHelper();
  const FAB_REPLACED = isFeatureEnable('FAB_REPLACEMENT');
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ExternalReferencesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: true,
      openExports: false,
      filters: emptyFilterGroup,
    },
  );
  const { sortBy, orderAsc, searchTerm, filters, numberOfElements } = viewStorage;
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<ExternalReferenceLine_node$data>(LOCAL_STORAGE_KEY);

  const contextFilters = useBuildEntityTypeBasedFilterContext('External-Reference', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ExternalReferencesLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<ExternalReferencesLinesPaginationQuery>(
    externalReferencesLinesQuery,
    queryPaginationOptions,
  );
  const renderLines = () => {
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns = {
      source_name: {
        label: 'Source name',
        width: '15%',
        isSortable: true,
      },
      external_id: {
        label: 'External ID',
        width: '10%',
        isSortable: true,
      },
      url: {
        label: 'URL',
        width: '45%',
        isSortable: true,
      },
      creator: {
        label: 'Creator',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      created: {
        label: 'Original creation date',
        width: '15%',
        isSortable: true,
      },
    };
    return (
      <>
        <ListLines
          helpers={helpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={helpers.handleSort}
          handleSearch={helpers.handleSearch}
          handleAddFilter={helpers.handleAddFilter}
          handleRemoveFilter={helpers.handleRemoveFilter}
          handleSwitchLocalMode={helpers.handleSwitchLocalMode}
          handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          displayImport={true}
          secondaryAction={true}
          filters={filters}
          keyword={searchTerm}
          iconExtension={true}
          paginationOptions={queryPaginationOptions}
          numberOfElements={numberOfElements}
          entityTypes={['External-Reference']}
          createButton={FAB_REPLACED && <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <ExternalReferenceCreation
              paginationOptions={queryPaginationOptions}
              openContextual={false}
            />
          </Security>}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <ExternalReferenceLineDummy
                        key={idx}
                        dataColumns={dataColumns}
                      />
                    ))}
                </>
                    }
            >
              <ExternalReferencesLines
                queryRef={queryRef}
                paginationOptions={queryPaginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={helpers.handleSetNumberOfElements}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
              />
            </React.Suspense>
          )}
        </ListLines>
        <ToolBar
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          numberOfSelectedElements={numberOfSelectedElements}
          handleClearSelectedElements={handleClearSelectedElements}
          selectAll={selectAll}
          search={searchTerm}
          filters={contextFilters}
          type="External-Reference"
        />
      </>
    );
  };
  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('External references'), current: true }]} />
      {renderLines()}
      {!FAB_REPLACED
        && <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ExternalReferenceCreation
            paginationOptions={queryPaginationOptions}
            openContextual={false}
          />
        </Security>
      }
    </ExportContextProvider>
  );
};

export default ExternalReferences;
