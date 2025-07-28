import React from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import StixDomainObjectKnowledge from '@components/common/stix_domain_objects/StixDomainObjectKnowledge';
import { SecurityPlatformKnowledge_securityPlatform$key } from '@components/entities/securityPlatforms/__generated__/SecurityPlatformKnowledge_securityPlatform.graphql';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';
import useAuth from '../../../../utils/hooks/useAuth';

const securityPlatformKnowledgeFragment = graphql`
  fragment SecurityPlatformKnowledge_securityPlatform on SecurityPlatform {
    id
    name
    description
    entity_type
    security_platform_type
  }
`;

const SecurityPlatformKnowledgeComponent = ({
  securityPlatformData,
}: {
  securityPlatformData: SecurityPlatformKnowledge_securityPlatform$key;
  relatedRelationshipTypes: string[];
}) => {
  const securityPlatform = useFragment(
    securityPlatformKnowledgeFragment,
    securityPlatformData,
  );
  const location = useLocation();
  const link = `/dashboard/entities/security_platforms/${securityPlatform.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(securityPlatform.entity_type, schema);
  return (
    <div data-testid="security-platform-knowledge">
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship
              entityId={securityPlatform.id}
              paddingRight={true}
            />
        }
        />
        <Route
          path="/overview"
          element={
            <StixDomainObjectKnowledge
              stixDomainObjectId={securityPlatform.id}
              stixDomainObjectType="SecurityPlatform"
            />
        }
        />
        <Route
          path="/all"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={securityPlatform.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              allDirections
              currentView={''}
              enableContextualView={false}
              isRelationReversed={true}
            />
        }
        />
        <Route
          path="/related"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={securityPlatform.id}
              relationshipTypes={['related-to']}
              entityLink={link}
              allDirections
              currentView={''}
              enableContextualView={false}
              isRelationReversed={true}
            />
         }
        />
        <Route
          path="/attack_patterns"
          element={
            <StixDomainObjectAttackPatterns
              stixDomainObjectId={securityPlatform.id}
              disableExport={false}
              entityType={securityPlatform.entity_type}
            />
        }
        />
      </Routes>
    </div>
  );
};

export default SecurityPlatformKnowledgeComponent;
