import React from 'react';
import * as PropTypes from 'prop-types';
import makeStyles from '@mui/styles/makeStyles';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import EntityStixCoreRelationshipsRelationshipsView from './EntityStixCoreRelationshipsRelationshipsView';
import EntityStixCoreRelationshipsEntitiesView from './EntityStixCoreRelationshipsEntitiesView';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';

const useStyles = makeStyles(() => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
}));

const EntityStixCoreRelationships = ({
  stixCoreObjectTypes,
  entityId,
  role,
  entityLink,
  disableExport,
  enableNestedView,
  enableContextualView,
  relationshipTypes,
  isRelationReversed,
  allDirections,
  defaultStartTime,
  defaultStopTime,
  currentView,
  paddingRightButtonAdd,
  handleChangeView,
}) => {
  const classes = useStyles();
  const localStorage = usePaginationLocalStorage(
    `view-relationships-${entityId}-${stixCoreObjectTypes?.join(
      '-',
    )}-${relationshipTypes?.join('-')}`,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
      filters: {},
      view: 'entities',
    },
  );
  const { view } = localStorage.viewStorage;

  const finalView = currentView || view;

  return (
      <ExportContextProvider>
        <div className={classes.container}>
          {finalView === 'entities'
            && <EntityStixCoreRelationshipsEntitiesView
              localStorage={localStorage}
              entityId={entityId}
              stixCoreObjectTypes={stixCoreObjectTypes}
              relationshipTypes={relationshipTypes}
              entityLink={entityLink}
              isRelationReversed={isRelationReversed}
              disableExport={disableExport}
              handleChangeView={handleChangeView}
              currentView={currentView}
              enableNestedView={enableNestedView}
              enableContextualView={enableContextualView}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              paddingRightButtonAdd={paddingRightButtonAdd}
            />}
           {finalView === 'relationships'
            && <EntityStixCoreRelationshipsRelationshipsView
            localStorage={localStorage}
            entityId={entityId}
            role={role}
            stixCoreObjectTypes={stixCoreObjectTypes}
            relationshipTypes={relationshipTypes}
            entityLink={entityLink}
            isRelationReversed={isRelationReversed}
            allDirections={allDirections}
            disableExport={disableExport}
            handleChangeView={handleChangeView}
            currentView={currentView}
            enableNestedView={enableNestedView}
            enableContextualView={enableContextualView}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
            paddingRightButtonAdd={paddingRightButtonAdd}
            />}
        </div>
      </ExportContextProvider>
  );
};

EntityStixCoreRelationships.propTypes = {
  entityId: PropTypes.string,
  role: PropTypes.string,
  stixCoreObjectTypes: PropTypes.array,
  relationshipTypes: PropTypes.array,
  entityLink: PropTypes.string,
  exploreLink: PropTypes.string,
  isRelationReversed: PropTypes.bool,
  allDirections: PropTypes.bool,
  noState: PropTypes.bool,
  disableExport: PropTypes.bool,
  handleChangeView: PropTypes.func,
  currentView: PropTypes.string,
  enableNestedView: PropTypes.bool,
  enableContextualView: PropTypes.bool,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
  paddingRightButtonAdd: PropTypes.string,
};

export default EntityStixCoreRelationships;
