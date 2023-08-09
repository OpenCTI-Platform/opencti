import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import EntityStixCoreRelationshipsRelationshipsView from './views/EntityStixCoreRelationshipsRelationshipsView';
import EntityStixCoreRelationshipsEntitiesView from './views/EntityStixCoreRelationshipsEntitiesView';
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
  enableNestedView?: boolean,
  enableContextualView: boolean,
  isRelationReversed: boolean;
  allDirections: boolean;
  role:string,
  paddingRightButtonAdd?: number,
  handleChangeView?: (viewMode: string) => void
}

const EntityStixCoreRelationships: FunctionComponent<EntityStixCoreRelationshipsProps> = ({
  entityId,
  entityLink,
  defaultStartTime,
  defaultStopTime,
  relationshipTypes,
  stixCoreObjectTypes,
  currentView,
  enableNestedView,
  enableContextualView,
  isRelationReversed,
  allDirections,
  role,
  paddingRightButtonAdd,
  handleChangeView,
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
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              relationshipTypes={relationshipTypes}
              stixCoreObjectTypes={stixCoreObjectTypes}
              currentView={currentView}
              enableNestedView={enableNestedView}
              enableContextualView={enableContextualView}
              isRelationReversed={isRelationReversed}
              paddingRightButtonAdd={paddingRightButtonAdd}
              handleChangeView={handleChangeView}
            />}
           {finalView === 'relationships'
            && <EntityStixCoreRelationshipsRelationshipsView
            localStorage={localStorage}
            entityId={entityId}
            entityLink={entityLink}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
            relationshipTypes={relationshipTypes}
            stixCoreObjectTypes={stixCoreObjectTypes}
            currentView={currentView}
            enableNestedView={enableNestedView}
            enableContextualView={enableContextualView}
            isRelationReversed={isRelationReversed}
            allDirections={allDirections}
            role={role}
            paddingRightButtonAdd={paddingRightButtonAdd}
            handleChangeView={handleChangeView}
            />}
        </div>
      </ExportContextProvider>
  );
};

export default EntityStixCoreRelationships;
