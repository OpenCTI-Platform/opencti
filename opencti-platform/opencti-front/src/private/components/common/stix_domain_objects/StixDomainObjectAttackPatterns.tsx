import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import {
  StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery,
  StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery.graphql';
import StixDomainObjectAttackPatternsKillChainContainer from '@components/common/stix_domain_objects/StixDomainObjectAttackPatternsKillChainContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery } from './StixDomainObjectAttackPatternsKillChain';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import {
  emptyFilterGroup,
  isFilterGroupNotEmpty,
  useAvailableFilterKeysForEntityTypes,
  useRemoveIdAndIncorrectKeysFromFilterGroupObject,
} from '../../../../utils/filters/filtersUtils';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
}));

interface StixDomainObjectAttackPatternsProps {
  stixDomainObjectId: string,
  entityLink: string,
  defaultStartTime: string,
  defaultStopTime: string,
  disableExport: boolean,
}

const StixDomainObjectAttackPatterns: FunctionComponent<StixDomainObjectAttackPatternsProps> = ({
  stixDomainObjectId,
  entityLink,
  defaultStartTime,
  defaultStopTime,
  disableExport,
}) => {
  const LOCAL_STORAGE_KEY = `attack-patterns-${stixDomainObjectId}`;
  const classes = useStyles();
  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery$variables>(LOCAL_STORAGE_KEY, {
    searchTerm: '',
    openExports: false,
    filters: emptyFilterGroup,
    view: 'matrix',
  });
  const { searchTerm, filters, view, openExports } = viewStorage;
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['stix-core-relationship']);
  const contextFilters = {
    mode: 'and',
    filters: [
      { key: 'elementWithTargetTypes', values: ['Attack-Pattern'] },
      { key: 'fromOrToId', values: [stixDomainObjectId] },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters } as unknown as StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery$variables;
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(['stix-core-relationship']);
  const queryRef = useQueryLoading<StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery>(
    stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery,
    { first: 500, ...queryPaginationOptions },
  );
  return (
    <div className={classes.container}>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixDomainObjectAttackPatternsKillChainContainer
            helpers={helpers}
            queryRef={queryRef}
            entityLink={entityLink}
            queryPaginationOptions={queryPaginationOptions}
            stixDomainObjectId={stixDomainObjectId}
            filters={filters}
            searchTerm={searchTerm}
            view={view}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
            disableExport={disableExport}
            openExports={openExports}
            availableFilterKeys={availableFilterKeys}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default StixDomainObjectAttackPatterns;
