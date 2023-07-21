import React, { FunctionComponent } from 'react';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import EntityStixCoreRelationshipsContextualView
  from './stix_cyber_observable/EntityStixCoreRelationshipsContextualView';
import EntityStixCoreRelationshipsRelationshipsView
  from './EntityStixCoreRelationshipsRelationshipsView';
import EntityStixCoreRelationshipsForIndicatorsEntitiesView
  from './EntityStixCoreRelationshipsForIndicatorsEntitiesView';
import { PaginationOptions } from '../../../../components/list_lines';

interface EntityStixCoreRelationshipsForStixDomainObjectIdIndicatorsProps {
  entityId: string
  entityLink: string
  defaultStartTime: string
  defaultStopTime: string
}

const EntityStixCoreRelationshipsForIndicators: FunctionComponent<EntityStixCoreRelationshipsForStixDomainObjectIdIndicatorsProps> = ({
  entityId,
  entityLink,
  defaultStartTime,
  defaultStopTime,
}) => {
  const relationshipTypes = ['indicates'];
  const entityTypes = ['Indicator'];

  const localStorage = usePaginationLocalStorage<PaginationOptions>(
    `view-relationships-${entityId}-${entityTypes?.join('-')}-${relationshipTypes?.join('-')}`,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      filters: {},
      view: 'entities',
    },
  );
  const { view } = localStorage.viewStorage;

  return (
    <ExportContextProvider>
      <div style={{ marginTop: 20 }}>
        {view === 'entities'
          && <EntityStixCoreRelationshipsForIndicatorsEntitiesView
            entityId={entityId}
            entityLink={entityLink}
            localStorage={localStorage}
            currentView={view}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
            enableContextualView={true}
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
            isRelationReversed={true}
            currentView={view}
            enableContextualView={true}
            enableNestedView={false}
          />}

        {view === 'contextual' && (
          <EntityStixCoreRelationshipsContextualView
            entityId={entityId}
            entityLink={entityLink}
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

export default EntityStixCoreRelationshipsForIndicators;
