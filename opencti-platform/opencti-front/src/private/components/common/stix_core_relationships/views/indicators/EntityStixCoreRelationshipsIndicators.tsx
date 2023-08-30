import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ExportContextProvider from '../../../../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../../../../utils/hooks/useLocalStorage';
import EntityStixCoreRelationshipsRelationshipsView from '../EntityStixCoreRelationshipsRelationshipsView';
import EntityStixCoreRelationshipsIndicatorsEntitiesView from './EntityStixCoreRelationshipsIndicatorsEntitiesView';
import { PaginationOptions } from '../../../../../../components/list_lines';
import EntityStixCoreRelationshipsIndicatorsContextualView from './EntityStixCoreRelationshipsIndicatorsContextualView';
import { initialFilterGroup } from '../../../../../../utils/filters/filtersUtils';

const useStyles = makeStyles(() => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
}));

interface EntityStixCoreRelationshipsIndicatorsProps {
  entityId: string
  entityLink: string
  defaultStartTime: string
  defaultStopTime: string
}

const EntityStixCoreRelationshipsIndicators: FunctionComponent<EntityStixCoreRelationshipsIndicatorsProps> = ({
  entityId,
  entityLink,
  defaultStartTime,
  defaultStopTime,
}) => {
  const classes = useStyles();

  const relationshipTypes = ['indicates'];
  const entityTypes = ['Indicator'];
  const LOCAL_STORAGE_KEY = `relationships-${entityId}-${entityTypes.join('-')}-${relationshipTypes.join('-')}`;

  const localStorage = usePaginationLocalStorage<PaginationOptions>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      filters: initialFilterGroup,
      view: 'entities',
    },
  );
  const { view } = localStorage.viewStorage;

  return (
    <ExportContextProvider>
      <div className={classes.container}>
        {view === 'entities'
          && <EntityStixCoreRelationshipsIndicatorsEntitiesView
            entityId={entityId}
            relationshipTypes={relationshipTypes}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
            localStorage={localStorage}
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
          <EntityStixCoreRelationshipsIndicatorsContextualView
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

export default EntityStixCoreRelationshipsIndicators;
