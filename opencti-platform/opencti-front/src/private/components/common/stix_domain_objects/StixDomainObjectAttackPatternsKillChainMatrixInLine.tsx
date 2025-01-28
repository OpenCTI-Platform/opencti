import React, { FunctionComponent, ReactElement } from 'react';
import {
  stixDomainObjectAttackPatternsKillChainContainerFragment,
  stixDomainObjectAttackPatternsKillChainContainerLineFragment,
} from '@components/common/stix_domain_objects/StixDomainObjectAttackPatternsKillChainContainer';
import { stixDomainObjectAttackPatternsKillChainQuery } from '@components/common/stix_domain_objects/StixDomainObjectAttackPatternsKillChain';
import {
  StixDomainObjectAttackPatternsKillChainQuery,
  StixDomainObjectAttackPatternsKillChainQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainQuery.graphql';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import DataTable from '../../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

interface StixDomainObjectAttackPatternsKillChainMatrixProps {
  storageKey: string;
  entityId: string;
  currentView?: string;
  viewButtons: ReactElement[];
  paginationOptions: StixDomainObjectAttackPatternsKillChainQuery$variables;
}

const StixDomainObjectAttackPatternsKillChainMatrixInline: FunctionComponent<StixDomainObjectAttackPatternsKillChainMatrixProps> = (
  {
    storageKey,
    entityId,
    currentView,
    paginationOptions,
    viewButtons,
  },
) => {
  const dataColumns = {
    entity_type: { percentWidth: 11 },
    killChainPhase: { percentWidth: 22 },
    x_mitre_id: { percentWidth: 10 },
    name: { percentWidth: 20 },
    objectLabel: { percentWidth: 15 },
    created: { percentWidth: 12 },
    objectMarking: { percentWidth: 10 },
  };

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
    view: currentView ?? 'matrix-in-line',
  };

  const { viewStorage, helpers: storageHelpers } = usePaginationLocalStorage<StixDomainObjectAttackPatternsKillChainQuery$variables>(
    storageKey,
    initialValues,
    true,
  );

  const {
    filters,
  } = viewStorage;

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Attack-Pattern']);
  const contextFilters = {
    mode: 'and',
    filters: [
      { key: 'entity_type', values: ['Attack-Pattern'], mode: 'or', operator: 'eq' },
      {
        key: 'regardingOf',
        values: [
          { key: 'id', values: [entityId] },
        ],
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as StixDomainObjectAttackPatternsKillChainQuery$variables;

  const queryRef = useQueryLoading<StixDomainObjectAttackPatternsKillChainQuery>(
    stixDomainObjectAttackPatternsKillChainQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: stixDomainObjectAttackPatternsKillChainQuery,
    linesFragment: stixDomainObjectAttackPatternsKillChainContainerFragment,
    queryRef,
    nodePath: ['attackPatterns', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixDomainObjectAttackPatternsKillChainQuery>;

  return (
    <div
      style={{
        transform: 'translateY(-12px)',
      }}
    >
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: StixDomainObjectAttackPatternsKillChainContainer_data$data) => (data.attackPatterns?.edges ?? []).map((n) => n.node)}
          storageKey={storageKey}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={stixDomainObjectAttackPatternsKillChainContainerLineFragment}
          exportContext={{ entity_type: 'Attack-Pattern' }}
          additionalHeaderButtons={[...viewButtons]}
        />
      )}
    </div>
  );
};

export default StixDomainObjectAttackPatternsKillChainMatrixInline;
