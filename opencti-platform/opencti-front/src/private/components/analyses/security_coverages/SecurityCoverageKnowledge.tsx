import React from 'react';
import { Route, Routes } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { SecurityCoverageKnowledge_securityCoverage$key } from './__generated__/SecurityCoverageKnowledge_securityCoverage.graphql';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';

const securityCoverageKnowledgeFragment = graphql`
  fragment SecurityCoverageKnowledge_securityCoverage on SecurityCoverage {
    id
    name
    description
    entity_type
    security_platform_type
  }
`;

const SecurityCoverageKnowledgeComponent = ({
  securityCoverageData,
}: {
  securityCoverageData: SecurityCoverageKnowledge_securityCoverage$key;
}) => {
  const securityCoverage = useFragment(
    securityCoverageKnowledgeFragment,
    securityCoverageData,
  );
  return (
    <div data-testid="security-coverage-knowledge">
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship
              entityId={securityCoverage.id}
              paddingRight={false}
            />
        }
        />
      </Routes>
    </div>
  );
};

export default SecurityCoverageKnowledgeComponent;
