import React from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import VulnerabilitiesLines, { vulnerabilitiesLinesQuery } from './vulnerabilities/VulnerabilitiesLines';
import VulnerabilityCreation from './vulnerabilities/VulnerabilityCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { Filters } from '../../../components/list_lines';
import { VulnerabilityLineDummy } from './vulnerabilities/VulnerabilityLine';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import {
  VulnerabilitiesLinesPaginationQuery,
  VulnerabilitiesLinesPaginationQuery$variables,
} from './vulnerabilities/__generated__/VulnerabilitiesLinesPaginationQuery.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useAuth from '../../../utils/hooks/useAuth';

const Vulnerabilities = () => {
  const { platformModuleHelpers } = useAuth();
  const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable() ?? false;
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<VulnerabilitiesLinesPaginationQuery$variables>(
    'view-vulnerabilities',
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: {} as Filters,
    },
  );

  const renderLines = () => {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = viewStorage;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '20%',
        isSortable: true,
      },
      x_opencti_base_severity: {
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

    const queryRef = useQueryLoading<VulnerabilitiesLinesPaginationQuery>(
      vulnerabilitiesLinesQuery,
      paginationOptions,
    );
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleToggleExports={helpers.handleToggleExports}
        openExports={openExports}
        exportEntityType="Vulnerability"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'labelledBy',
          'markedBy',
          'created_start_date',
          'created_end_date',
          'x_opencti_base_score',
          'x_opencti_base_severity',
          'x_opencti_attack_vector',
          'createdBy',
          'creator',
          'confidence',
        ]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((idx) => (
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
              paginationOptions={paginationOptions}
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
    <div>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <VulnerabilityCreation paginationOptions={paginationOptions} />
      </Security>
    </div>
  );
};

export default Vulnerabilities;
