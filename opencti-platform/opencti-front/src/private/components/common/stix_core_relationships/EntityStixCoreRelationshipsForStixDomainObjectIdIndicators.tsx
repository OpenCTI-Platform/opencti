import React, { FunctionComponent } from 'react';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import EntityStixCoreRelationshipsContextualView
  from './stix_cyber_observable/EntityStixCoreRelationshipsContextualView';
import EntityStixCoreRelationshipsRelationshipsView
  from './EntityStixCoreRelationshipsRelationshipsView';
import EntityStixCoreRelationshipsForStixDomainObjectIdIndicatorsEntitiesView
  from './EntityStixCoreRelationshipsForStixDomainObjectIdIndicatorsEntitiesView';
import { PaginationOptions } from '../../../../components/list_lines';

interface EntityStixCoreRelationshipsForStixDomainObjectIdIndicatorsProps {
  entityId: string
  entityLink: string
  defaultStartTime: string
  defaultStopTime: string
}

const EntityStixCoreRelationshipsForStixDomainObjectIdIndicators: FunctionComponent<EntityStixCoreRelationshipsForStixDomainObjectIdIndicatorsProps> = ({
  entityId,
  entityLink,
  defaultStartTime,
  defaultStopTime,
}) => {
  const relationshipTypes = ['indicates'];
  const entityTypes = ['Stix-Cyber-Indicators'];

  const localStorage = usePaginationLocalStorage<PaginationOptions>(
    `view-indicators-${entityId}`,
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
          && <EntityStixCoreRelationshipsForStixDomainObjectIdIndicatorsEntitiesView
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
            allDirections={true}
            currentView={view}
            enableContextualView={true}
            enableNestedView={true}
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

export default EntityStixCoreRelationshipsForStixDomainObjectIdIndicators;
