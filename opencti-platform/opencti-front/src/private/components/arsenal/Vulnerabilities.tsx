import React from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import VulnerabilitiesLines, { vulnerabilitiesLinesQuery } from './vulnerabilities/VulnerabilitiesLines';
import VulnerabilityCreation from './vulnerabilities/VulnerabilityCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { VulnerabilityLineDummy } from './vulnerabilities/VulnerabilityLine';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { VulnerabilitiesLinesPaginationQuery, VulnerabilitiesLinesPaginationQuery$variables } from './vulnerabilities/__generated__/VulnerabilitiesLinesPaginationQuery.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useAuth from '../../../utils/hooks/useAuth';
import { buildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';

const LOCAL_STORAGE_KEY = 'vulnerabilities';

const Vulnerabilities = () => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<VulnerabilitiesLinesPaginationQuery$variables>(
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

  const contextFilters = buildEntityTypeBasedFilterContext('Vulnerability', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as VulnerabilitiesLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<VulnerabilitiesLinesPaginationQuery>(
    vulnerabilitiesLinesQuery,
    queryPaginationOptions,
  );

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '20%',
        isSortable: true,
      },
      x_opencti_cvss_base_severity: {
        label: 'CVSS3 - Severity',
        width: '15%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '12%',
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
      creator: {
        label: 'Creators',
        width: '12%',
        isSortable: isRuntimeSort,
      },
    };

    return (
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
        exportContext={{ entity_type: 'Vulnerability' }}
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
          'x_opencti_cvss_base_score',
          'x_opencti_cvss_base_severity',
          'x_opencti_cvss_attack_vector',
          'creator_id',
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
                    <VulnerabilityLineDummy
                      key={idx}
                      dataColumns={dataColumns}
                    />
                  ))}
              </>
            }
          >
            <VulnerabilitiesLines
              queryRef={queryRef}
              paginationOptions={queryPaginationOptions}
              dataColumns={dataColumns}
              onLabelClick={helpers.handleAddFilter}
              setNumberOfElements={helpers.handleSetNumberOfElements}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };

  return (
    <>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <VulnerabilityCreation paginationOptions={queryPaginationOptions} />
      </Security>
    </>
  );
};

export default Vulnerabilities;
