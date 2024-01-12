import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Loader from '../../../../components/Loader';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectAttackPatternsKillChain, { stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery } from './StixDomainObjectAttackPatternsKillChain';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup, removeIdFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';

const useStyles = makeStyles(() => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
}));

const StixDomainObjectAttackPatterns = ({
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
  } = usePaginationLocalStorage(LOCAL_STORAGE_KEY, {
    searchTerm: '',
    openExports: false,
    filters: emptyFilterGroup,
    view: 'matrix',
  });
  const { searchTerm, filters, view, openExports } = viewStorage;
  const userFilters = removeIdFromFilterGroupObject(filters);
  const contextFilters = {
    mode: 'and',
    filters: [
      { key: 'elementWithTargetTypes', values: ['Attack-Pattern'] },
      { key: 'fromOrToId', values: [stixDomainObjectId] },
    ],
    filterGroups: userFilters ? [userFilters] : [],
  };
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters };
  return (
    <div className={classes.container}>
      <QueryRenderer
        query={stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery}
        variables={{ first: 500, ...queryPaginationOptions }}
        render={({ props }) => {
          if (props) {
            return (
              <StixDomainObjectAttackPatternsKillChain
                data={props}
                entityLink={entityLink}
                paginationOptions={queryPaginationOptions}
                stixDomainObjectId={stixDomainObjectId}
                handleChangeView={helpers.handleChangeView}
                handleSearch={helpers.handleSearch}
                handleAddFilter={helpers.handleAddFilter}
                handleRemoveFilter={helpers.handleRemoveFilter}
                handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
                handleSwitchLocalMode={helpers.handleSwitchLocalMode}
                filters={filters}
                searchTerm={searchTerm ?? ''}
                currentView={view}
                defaultStartTime={defaultStartTime}
                defaultStopTime={defaultStopTime}
                handleToggleExports={
                  disableExport ? null : helpers.handleToggleExports
                }
                openExports={openExports}
              />
            );
          }
          return <Loader withRightPadding={true} />;
        }}
      />
    </div>
  );
};

export default StixDomainObjectAttackPatterns;
