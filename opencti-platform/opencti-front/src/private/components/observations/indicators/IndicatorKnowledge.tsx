import { Route, Routes } from 'react-router-dom';
import IndicatorEntities from './IndicatorEntities';
import StixCoreRelationship from '@components/common/stix_core_relationships/StixCoreRelationship';
import StixSightingRelationship from '@components/events/stix_sighting_relationships/StixSightingRelationship';

interface IndicatorKnowledgeProps {
  indicatorId: string;
}

const IndicatorKnowledge = ({ indicatorId }: IndicatorKnowledgeProps) => (
  <Routes>
    <Route
      index
      element={(
        <IndicatorEntities
          indicatorId={indicatorId}
          relationshipType={undefined}
          defaultStartTime={undefined}
          defaultStopTime={undefined}
        />
      )}
    />
    <Route
      path="/relations/:relationId"
      element={(
        <StixCoreRelationship
          entityId={indicatorId}
        />
      )}
    />
    <Route
      path="/sightings/:sightingId"
      element={(
        <StixSightingRelationship
          entityId={indicatorId}
          paddingRight
        />
      )}
    />
  </Routes>
);

export default IndicatorKnowledge;
