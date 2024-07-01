import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import StixDomainObjectAttackPatternsKillChainContainer from '@components/common/stix_domain_objects/StixDomainObjectAttackPatternsKillChainContainer';
import {
  StixDomainObjectAttackPatternsKillChainQuery,
  StixDomainObjectAttackPatternsKillChainQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { stixDomainObjectAttackPatternsKillChainQuery } from './StixDomainObjectAttackPatternsKillChain';
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
  defaultStartTime: string,
  defaultStopTime: string,
  disableExport: boolean,
}

const StixDomainObjectAttackPatterns: FunctionComponent<StixDomainObjectAttackPatternsProps> = ({
  stixDomainObjectId,
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
  } = usePaginationLocalStorage<StixDomainObjectAttackPatternsKillChainQuery$variables>(LOCAL_STORAGE_KEY, {
    searchTerm: '',
    openExports: false,
    filters: emptyFilterGroup,
    view: 'matrix',
  });
  const { searchTerm, filters, view, openExports } = viewStorage;
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Attack-Pattern']);
  const contextFilters = {
    mode: 'and',
    filters: [
      { key: 'entity_type', values: ['Attack-Pattern'], mode: 'or', operator: 'eq' },
      {
        key: 'regardingOf',
        values: [
          { key: 'id', values: [stixDomainObjectId] },
        ],
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
    search: searchTerm } as unknown as StixDomainObjectAttackPatternsKillChainQuery$variables;
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(['Attack-Pattern']);
  const queryRef = useQueryLoading<StixDomainObjectAttackPatternsKillChainQuery>(
    stixDomainObjectAttackPatternsKillChainQuery,
    { first: 500, ...queryPaginationOptions },
  );
  return (
    <div className={classes.container}>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixDomainObjectAttackPatternsKillChainContainer
            helpers={helpers}
            queryRef={queryRef}
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
