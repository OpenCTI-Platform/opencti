import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import EntityStixCoreRelationshipsRelationshipsView from './EntityStixCoreRelationshipsRelationshipsView';
import EntityStixCoreRelationshipsEntitiesView from './EntityStixCoreRelationshipsEntitiesView';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { PaginationOptions } from '../../../../components/list_lines';

const useStyles = makeStyles(() => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
}));

interface EntityStixCoreRelationshipsProps {
  entityId: string
  entityLink: string
  defaultStartTime: string
  defaultStopTime: string
  relationshipTypes: string[]
  stixCoreObjectTypes: string[]
  currentView: string
  enableNestedView: boolean,
  enableContextualView: boolean,
  isRelationReversed: boolean;
  allDirections: boolean;
  role:string,
  paddingRightButtonAdd?: number,
}

const EntityStixCoreRelationships: FunctionComponent<EntityStixCoreRelationshipsProps> = ({
  stixCoreObjectTypes,
  entityId,
  role,
  entityLink,
  enableNestedView,
  enableContextualView,
  relationshipTypes,
  isRelationReversed,
  allDirections,
  defaultStartTime,
  defaultStopTime,
  currentView,
  paddingRightButtonAdd,
}) => {
  const classes = useStyles();
  const localStorage = usePaginationLocalStorage<PaginationOptions>(
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

export default EntityStixCoreRelationships;
