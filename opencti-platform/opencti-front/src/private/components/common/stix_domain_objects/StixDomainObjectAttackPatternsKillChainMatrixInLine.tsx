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
import StixCoreRelationshipCreationFromEntity from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import DataTable from '../../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { useQueryLoadingWithLoadQuery } from '../../../../utils/hooks/useQueryLoading';

interface StixDomainObjectAttackPatternsKillChainMatrixProps {
  storageKey: string;
  entityId: string;
  currentView?: string;
  viewButtons: ReactElement[];
  defaultStartTime: string;
  defaultStopTime: string;
}

const StixDomainObjectAttackPatternsKillChainMatrixInline: FunctionComponent<StixDomainObjectAttackPatternsKillChainMatrixProps> = (
  {
    storageKey,
    entityId,
    currentView,
    viewButtons,
    defaultStartTime,
    defaultStopTime,
  },
) => {
  const LOCAL_STORAGE_KEY = `${storageKey}-stix-matrix-in-line`;
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

  const { paginationOptions, viewStorage, helpers: storageHelpers } = usePaginationLocalStorage<StixDomainObjectAttackPatternsKillChainQuery$variables>(
    LOCAL_STORAGE_KEY,
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

  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<StixDomainObjectAttackPatternsKillChainQuery>(
    stixDomainObjectAttackPatternsKillChainQuery,
    queryPaginationOptions,
  );

  const refetch = React.useCallback(() => {
    loadQuery(queryPaginationOptions, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);

  const preloadedPaginationProps = {
    linesQuery: stixDomainObjectAttackPatternsKillChainQuery,
    linesFragment: stixDomainObjectAttackPatternsKillChainContainerFragment,
    queryRef,
    nodePath: ['attackPatterns', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixDomainObjectAttackPatternsKillChainQuery>;

  return (
    <>
      <div
        style={{
          transform: 'translateY(-12px)',
        }}
      >
        {queryRef && (
          <DataTable
            variant={DataTableVariant.inline}
            dataColumns={dataColumns}
            resolvePath={(data: StixDomainObjectAttackPatternsKillChainContainer_data$data) => (data.attackPatterns?.edges ?? []).map((n) => n.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            toolbarFilters={contextFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            lineFragment={stixDomainObjectAttackPatternsKillChainContainerLineFragment}
            exportContext={{ entity_type: 'Attack-Pattern' }}
            additionalHeaderButtons={[...viewButtons]}
          />
        )}
      </div>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <StixCoreRelationshipCreationFromEntity
          entityId={entityId}
          isRelationReversed={false}
          paddingRight={220}
          onCreate={refetch}
          targetStixDomainObjectTypes={['Attack-Pattern']}
          paginationOptions={queryPaginationOptions}
          defaultStartTime={defaultStartTime}
          defaultStopTime={defaultStopTime}
        />
      </Security>
    </>
  );
};

export default StixDomainObjectAttackPatternsKillChainMatrixInline;
