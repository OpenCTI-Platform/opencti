import React from 'react';
import {
  EntitiesStixDomainObjectsLinesPaginationQuery,
  EntitiesStixDomainObjectsLinesPaginationQuery$variables,
} from '@components/data/entities/__generated__/EntitiesStixDomainObjectsLinesPaginationQuery.graphql';
import { EntitiesStixDomainObjectsLines_data$data } from '@components/data/entities/__generated__/EntitiesStixDomainObjectsLines_data.graphql';
import { entitiesFragment } from '@components/data/entities/EntitiesStixDomainObjectLine';
import { entitiesStixDomainObjectsLinesFragment, entitiesStixDomainObjectsLinesQuery } from './entities/EntitiesStixDomainObjectsLines';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';

const LOCAL_STORAGE_KEY = 'entities';

const Entities = () => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['entity_type'], ['Stix-Core-Object']),
    },
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
  };
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<EntitiesStixDomainObjectsLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, initialValues);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Domain-Object', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as EntitiesStixDomainObjectsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<EntitiesStixDomainObjectsLinesPaginationQuery>(
    entitiesStixDomainObjectsLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const dataColumns: DataTableProps['dataColumns'] = {
    entity_type: { percentWidth: 13 },
    name: {},
    createdBy: { isSortable: isRuntimeSort },
    creator: { isSortable: isRuntimeSort },
    objectLabel: {},
    created_at: {},
    objectMarking: { isSortable: isRuntimeSort },
  };

  const preloadedPaginationProps = {
    linesQuery: entitiesStixDomainObjectsLinesQuery,
    linesFragment: entitiesStixDomainObjectsLinesFragment,
    queryRef,
    nodePath: ['stixDomainObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<EntitiesStixDomainObjectsLinesPaginationQuery>;

  return (
    <div data-testid='data-entities-page'>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Data') }, { label: t_i18n('Entities'), current: true }]} />
      {queryRef && (
        <DataTable
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          preloadedPaginationProps={preloadedPaginationProps}
          resolvePath={(data: EntitiesStixDomainObjectsLines_data$data) => data.stixDomainObjects?.edges?.map((n) => n?.node)}
          dataColumns={dataColumns}
          lineFragment={entitiesFragment}
          toolbarFilters={contextFilters}
          exportContext={{ entity_type: 'Stix-Domain-Object' }}
          availableEntityTypes={['Stix-Domain-Object']}
        />
      )}
    </div>
  );
};

export default Entities;
