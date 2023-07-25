import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import EntityStixCoreRelationshipsContextualView from '../EntityStixCoreRelationshipsContextualView';
import { usePaginationLocalStorage } from '../../../../../../utils/hooks/useLocalStorage';
import { PaginationOptions } from '../../../../../../components/list_lines';
import EntityStixCoreRelationshipsEntitiesView from '../EntityStixCoreRelationshipsEntitiesView';
import EntityStixCoreRelationshipsRelationshipsView from '../EntityStixCoreRelationshipsRelationshipsView';
import ExportContextProvider from '../../../../../../utils/ExportContextProvider';

const useStyles = makeStyles(() => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
}));

interface EntityStixCoreRelationshipsForStixCyberObservableProps {
  entityId: string
  entityLink: string
  defaultStartTime: string
  defaultStopTime: string
}

const EntityStixCoreRelationshipsStixCyberObservable: FunctionComponent<EntityStixCoreRelationshipsForStixCyberObservableProps> = (props) => {
  const classes = useStyles();

  const { entityId, entityLink, defaultStartTime, defaultStopTime } = props;
  const relationshipTypes = ['related-to'];
  const entityTypes = ['Stix-Cyber-Observable'];

  const localStorage = usePaginationLocalStorage<PaginationOptions>(
    `view-relationships-${entityId}-${entityTypes.join('-')}-${relationshipTypes.join('-')}`,
    {
      numberOfElements: { number: 0, symbol: '', original: 0 },
      filters: {},
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
      view: 'entities',
    },
  );
  const { view } = localStorage.viewStorage;

  return (
    <ExportContextProvider>
      <div className={classes.container}>
        {view === 'entities'
          && <EntityStixCoreRelationshipsEntitiesView
            entityId={entityId}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
            localStorage={localStorage}
            relationshipTypes={relationshipTypes}
            stixCoreObjectTypes={entityTypes}
            isRelationReversed
            currentView={view}
            enableContextualView
          />}

        {view === 'relationships'
          && <EntityStixCoreRelationshipsRelationshipsView
            entityId={entityId}
            entityLink={entityLink}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
            localStorage={localStorage}
            relationshipTypes={relationshipTypes}
            stixCoreObjectTypes={entityTypes}
            isRelationReversed
            currentView={view}
            enableContextualView
          />}

        {view === 'contextual' && (
          <EntityStixCoreRelationshipsContextualView
            entityId={entityId}
            localStorage={localStorage}
            relationshipTypes={relationshipTypes}
            stixCoreObjectTypes={entityTypes}
            currentView={view}
          />
        )}
      </div>
    </ExportContextProvider>
  );
};

export default EntityStixCoreRelationshipsStixCyberObservable;
