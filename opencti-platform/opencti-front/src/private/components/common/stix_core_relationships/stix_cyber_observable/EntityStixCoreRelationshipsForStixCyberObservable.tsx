import React, { FunctionComponent, useState } from 'react';
import EntityStixCoreRelationships from '../EntityStixCoreRelationships';
import EntityStixCoreRelationshipsContextualView from './EntityStixCoreRelationshipsContextualView';
import { usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import { PaginationOptions } from '../../../../../components/list_lines';

interface EntityStixCoreRelationshipsForStixCyberObservableProps {
  entityId: string
  entityLink: string
  defaultStartTime: string
  defaultStopTime: string
}

const EntityStixCoreRelationshipsForStixCyberObservable: FunctionComponent<EntityStixCoreRelationshipsForStixCyberObservableProps> = (props) => {
  const { entityId, entityLink, defaultStartTime, defaultStopTime } = props;
  const relationshipTypes = ['related-to'];
  const entityTypes = ['Stix-Cyber-Observable'];

  const paginationLocalStorage = usePaginationLocalStorage<PaginationOptions>(
    `view-relationships-${entityId}-${entityTypes?.join('-')}-${relationshipTypes?.join('-')}`,
    {
      numberOfElements: { number: 0, symbol: '', original: 0 },
      filters: {},
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
    },
  );

  const [viewMode, setViewMode] = useState('entities');

  return (
    <>
      {viewMode === 'contextual' && (
        <EntityStixCoreRelationshipsContextualView
        entityId={entityId}
        entityLink={entityLink}
        relationshipTypes={relationshipTypes}
        stixCoreObjectTypes={entityTypes}
        currentView={viewMode}
        handleChangeView={setViewMode}
        paginationLocalStorage={paginationLocalStorage}
        />
      )}
      {viewMode !== 'contextual' && (
        <EntityStixCoreRelationships
          entityId={entityId}
          entityLink={entityLink}
          relationshipTypes={relationshipTypes}
          stixCoreObjectTypes={entityTypes}
          defaultStartTime={defaultStartTime}
          defaultStopTime={defaultStopTime}
          allDirections={true} // For any entities
          isRelationReversed={true} // For any entities
          enableContextualView={true}
          currentView={viewMode}
          handleChangeView={setViewMode}
        />
      )}
    </>
  );
};

export default EntityStixCoreRelationshipsForStixCyberObservable;
