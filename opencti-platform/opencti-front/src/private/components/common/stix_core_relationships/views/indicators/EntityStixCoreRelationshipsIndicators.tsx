import React, { FunctionComponent } from 'react';
import Box from '@mui/material/Box';
import ExportContextProvider from '../../../../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../../../../utils/hooks/useLocalStorage';
import EntityStixCoreRelationshipsRelationshipsView from '../EntityStixCoreRelationshipsRelationshipsView';
import EntityStixCoreRelationshipsIndicatorsEntitiesView from './EntityStixCoreRelationshipsIndicatorsEntitiesView';
import { PaginationOptions } from '../../../../../../components/list_lines';
import EntityStixCoreRelationshipsIndicatorsContextualView from './EntityStixCoreRelationshipsIndicatorsContextualView';
import { emptyFilterGroup } from '../../../../../../utils/filters/filtersUtils';

interface EntityStixCoreRelationshipsIndicatorsProps {
  entityId: string;
  entityLink: string;
  defaultStartTime: string;
  defaultStopTime: string;
  relationshipTypes?: string[];
}

const EntityStixCoreRelationshipsIndicators: FunctionComponent<EntityStixCoreRelationshipsIndicatorsProps> = ({
  entityId,
  entityLink,
  defaultStartTime,
  defaultStopTime,
  relationshipTypes = ['indicates'],
}) => {
  const entityTypes = ['Indicator'];
  const LOCAL_STORAGE_KEY = `indicators-relationships-${entityId}-${entityTypes.join('-')}-${relationshipTypes.join('-')}`;
  const localStorage = usePaginationLocalStorage<PaginationOptions>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      filters: emptyFilterGroup,
      view: 'entities',
    },
  );
  const { view } = localStorage.viewStorage;
  return (
    <ExportContextProvider>
      <Box sx={{ marginTop: '15px', paddingBottom: '70px' }}>
        {view === 'entities'
          && (
            <EntityStixCoreRelationshipsIndicatorsEntitiesView
              entityId={entityId}
              relationshipTypes={relationshipTypes}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              localStorage={localStorage}
              isRelationReversed
              currentView={view}
            />
          )}

        {view === 'relationships'
          && (
            <EntityStixCoreRelationshipsRelationshipsView
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
            />
          )}

        {view === 'contextual' && (
          <EntityStixCoreRelationshipsIndicatorsContextualView
            entityId={entityId}
            localStorage={localStorage}
            relationshipTypes={relationshipTypes}
            stixCoreObjectTypes={entityTypes}
            currentView={view}
          />
        )}
      </Box>
    </ExportContextProvider>
  );
};

export default EntityStixCoreRelationshipsIndicators;
