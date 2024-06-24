import { FunctionComponent } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import {
  StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery,
  StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery.graphql';
import StixDomainObjectAttackPatternsKillChain, { stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery } from './StixDomainObjectAttackPatternsKillChain';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

interface StixDomainObjectAttackPatternsKillChainProps {
  helpers: UseLocalStorageHelpers;
  queryRef: PreloadedQuery<StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery>;
  entityLink: string;
  queryPaginationOptions: StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery$variables;
  stixDomainObjectId: string;
  filters?: FilterGroup;
  searchTerm?: string;
  view?: string;
  defaultStartTime: string;
  defaultStopTime: string;
  disableExport: boolean;
  openExports?: boolean;
  availableFilterKeys: string[];
}

const StixDomainObjectAttackPatternsKillChainContainer: FunctionComponent<StixDomainObjectAttackPatternsKillChainProps> = ({
  helpers,
  queryRef,
  entityLink,
  queryPaginationOptions,
  stixDomainObjectId,
  filters,
  searchTerm,
  view,
  defaultStartTime,
  defaultStopTime,
  disableExport,
  openExports,
  availableFilterKeys,
}) => {
  const data = usePreloadedPaginationFragment(stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery, queryRef);
  console.log('data', data);
  return (
    <StixDomainObjectAttackPatternsKillChain
      data={data}
      entityLink={entityLink}
      paginationOptions={queryPaginationOptions}
      stixDomainObjectId={stixDomainObjectId}
      handleChangeView={helpers.handleChangeView}
      handleSearch={helpers.handleSearch}
      helpers={helpers}
      filters={filters}
      searchTerm={searchTerm ?? ''}
      currentView={view}
      defaultStartTime={defaultStartTime}
      defaultStopTime={defaultStopTime}
      exportContext={{ entity_type: 'stix-core-relationship' }}
      handleToggleExports={disableExport ? null : helpers.handleToggleExports}
      openExports={openExports}
      availableFilterKeys={availableFilterKeys}
    />
  );
};

export default StixDomainObjectAttackPatternsKillChainContainer;
