import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import { Route, Routes } from 'react-router-dom';
import StixCyberObservableKnowledgeEntities from './StixCyberObservableEntities';
import StixCyberObservableNestedEntities from './StixCyberObservableNestedEntities';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';

const StixCyberObservableKnowledgeComponent = (props) => {
  const { stixCyberObservable } = props;
  return (
    <>
      <Routes>
        <Route
          path="/relations/:relationId/"
          element={
            <StixCoreRelationship
              entityId={stixCyberObservable.id}
            />
          }
        />
      </Routes>
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
    </>
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
