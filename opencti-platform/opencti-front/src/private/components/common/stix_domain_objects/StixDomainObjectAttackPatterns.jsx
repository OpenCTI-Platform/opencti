import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Loader from '../../../../components/Loader';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectAttackPatternsKillChain, {
  stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery,
} from './StixDomainObjectAttackPatternsKillChain';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';

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
  const LOCAL_STORAGE_KEY = `view-attack-patterns-${stixDomainObjectId}`;
  const classes = useStyles();

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      openExports: false,
      filters: {},
      view: 'matrix',
    },
  );
  const {
    searchTerm,
    filters,
    view,
    openExports,
  } = viewStorage;

  const finalPaginationOptions = {
    elementId: stixDomainObjectId,
    elementWithTargetTypes: ['Attack-Pattern'],
    ...paginationOptions,
  };
  return (
      <div className={classes.container}>
        <QueryRenderer
          query={
            stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery
          }
          variables={{ first: 500, ...finalPaginationOptions }}
          render={({ props }) => {
            if (props) {
              return (
                <StixDomainObjectAttackPatternsKillChain
                  data={props}
                  entityLink={entityLink}
                  paginationOptions={finalPaginationOptions}
                  stixDomainObjectId={stixDomainObjectId}
                  handleChangeView={helpers.handleChangeView}
                  handleSearch={helpers.handleSearch}
                  handleAddFilter={helpers.handleAddFilter}
                  handleRemoveFilter={helpers.handleRemoveFilter}
                  filters={filters}
                  searchTerm={searchTerm}
                  currentView={view}
                  defaultStartTime={defaultStartTime}
                  defaultStopTime={defaultStopTime}
                  handleToggleExports={disableExport ? null : helpers.handleToggleExports}
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
