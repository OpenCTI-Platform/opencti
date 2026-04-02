import { Route, Routes } from 'react-router-dom';
import StixCoreRelationship from '@components/common/stix_core_relationships/StixCoreRelationship';
import StixSightingRelationship from '@components/events/stix_sighting_relationships/StixSightingRelationship';
import StixCyberObservableKnowledge from '../stix_cyber_observables/StixCyberObservableKnowledge';
import { RootArtifactQuery$data } from './__generated__/RootArtifactQuery.graphql';

interface ArtifactKnowledgeProps {
  artifact: NonNullable<RootArtifactQuery$data['stixCyberObservable']>;
  connectorsForImport: NonNullable<RootArtifactQuery$data['connectorsForImport']>;
}

const ArtifactKnowledge = ({ artifact, connectorsForImport }: ArtifactKnowledgeProps) => (
  <Routes>
    <Route
      index
      element={(
        <StixCyberObservableKnowledge
          stixCyberObservable={artifact}
          connectorsForImport={connectorsForImport}
        />
      )}
    />
    <Route
      path="/relations/:relationId"
      element={(
        <StixCoreRelationship
          entityId={artifact.id}
        />
      )}
    />
    <Route
      path="/sightings/:sightingId"
      element={(
        <StixSightingRelationship
          entityId={artifact.id}
          paddingRight
        />
      )}
    />
  </Routes>
);

export default ArtifactKnowledge;
