import { Route, Routes } from 'react-router-dom';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';

const SecurityCoverageKnowledgeComponent = () => {
  return (
    <div data-testid="security-coverage-knowledge">
      <Routes>
        <Route
          path="/relations/:relationId"
          element={(
            <StixCoreRelationship />
          )}
        />
      </Routes>
    </div>
  );
};

export default SecurityCoverageKnowledgeComponent;
