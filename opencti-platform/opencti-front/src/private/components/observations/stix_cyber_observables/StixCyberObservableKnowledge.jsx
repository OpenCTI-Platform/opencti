import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import { Route, Routes } from 'react-router-dom';
import StixSightingRelationship from '@components/events/stix_sighting_relationships/StixSightingRelationship';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixCyberObservableKnowledgeEntities from './StixCyberObservableEntities';
import StixCyberObservableNestedEntities from './StixCyberObservableNestedEntities';

const StixCyberObservableKnowledgeComponent = (props) => {
  const { stixCyberObservable } = props;
  return (
    <Routes>
      <Route
        index
        element={(
          <div data-testid="observable-knowledge">
            <div style={{ marginTop: 20 }}>
              <StixCyberObservableNestedEntities
                entityId={stixCyberObservable.id}
                entityType={stixCyberObservable.entity_type}
              />
            </div>
            <div style={{ marginTop: 40 }}>
              <StixCyberObservableKnowledgeEntities
                entityId={stixCyberObservable.id}
              />
            </div>
          </div>
        )}
      />
      <Route
        path="/relations/:relationId"
        element={(
          <StixCoreRelationship
            entityId={stixCyberObservable.id}
          />
        )}
      />
      <Route
        path="/sightings/:sightingId"
        element={(
          <StixSightingRelationship
            entityId={stixCyberObservable.id}
            paddingRight
          />
        )}
      />
    </Routes>
  );
};

const StixCyberObservableKnowledge = createFragmentContainer(
  StixCyberObservableKnowledgeComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableKnowledge_stixCyberObservable on StixCyberObservable {
        id
        entity_type
        ...StixCyberObservableHeader_stixCyberObservable
        ...StixCyberObservableIndicators_stixCyberObservable
      }
    `,
  },
);

export default StixCyberObservableKnowledge;
