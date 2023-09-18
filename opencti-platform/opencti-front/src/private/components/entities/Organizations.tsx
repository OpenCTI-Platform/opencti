import React from 'react';
import {
  OrganizationsLinesPaginationQuery, OrganizationsLinesPaginationQuery$variables,
} from '@components/entities/organizations/__generated__/OrganizationsLinesPaginationQuery.graphql';
import { OrganizationLineDummy } from '@components/entities/organizations/OrganizationLine';
import ListLines from '../../../components/list_lines/ListLines';
import OrganizationsLines, { organizationsLinesQuery } from './organizations/OrganizationsLines';
import OrganizationCreation from './organizations/OrganizationCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../components/list_lines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'view-organizations';

const Organizations = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<OrganizationsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
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
        width: '23%',
        isSortable: true,
      },
      x_opencti_organization_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '23%',
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
    const queryRef = useQueryLoading<OrganizationsLinesPaginationQuery>(
      organizationsLinesQuery,
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
        exportEntityType="Organization"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'x_opencti_organization_type',
          'labelledBy',
          'markedBy',
          'createdBy',
          'created_start_date',
          'created_end_date',
          'x_opencti_reliability',
        ]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((idx) => (
                    <OrganizationLineDummy
                      key={idx}
                      dataColumns={dataColumns}
                    />
                  ))}
              </>
            }
          >
            <OrganizationsLines
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
        <OrganizationCreation paginationOptions={paginationOptions} />
      </Security>
    </div>
  );
};

export default Organizations;
