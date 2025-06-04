import React from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import StixDomainObjectKnowledge from '@components/common/stix_domain_objects/StixDomainObjectKnowledge';
import { SecurityPlatformKnowledge_securityPlatform$key } from '@components/entities/securityPlatforms/__generated__/SecurityPlatformKnowledge_securityPlatform.graphql';
import StixDomainObjectAuthorKnowledge from '@components/common/stix_domain_objects/StixDomainObjectAuthorKnowledge';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import EntityStixCoreRelationshipsIndicators from '../../common/stix_core_relationships/views/indicators/EntityStixCoreRelationshipsIndicators';
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
  viewAs,
}: {
  securityPlatformData: SecurityPlatformKnowledge_securityPlatform$key;
  relatedRelationshipTypes: string[];
  viewAs: string;
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
    <>
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
          element={(viewAs === 'knowledge' ? (
            <StixDomainObjectKnowledge
              stixDomainObjectId={securityPlatform.id}
              stixDomainObjectType="SecurityPlatform"
            />
          ) : (
            <StixDomainObjectAuthorKnowledge
              stixDomainObjectId={securityPlatform.id}
              stixDomainObjectType="SecurityPlatform"
            />
          ))
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
              enableContextualView={true}
              isRelationReversed={true}
            />
        }
        />
        <Route
          path="/systems"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={securityPlatform.id}
              relationshipTypes={['part-of']}
              stixCoreObjectTypes={['System']}
              entityLink={link}
              currentView={''}
              enableContextualView={true}
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
              stixCoreObjectTypes={['Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Incident',
                'Malware',
                'Tool',
                'Vulnerability',
                'Individual',
                'Organization',
                'Sector',
                'Region',
                'Country',
                'City',
                'Position']}
              currentView={''}
              enableContextualView={true}
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
            />
        }
        />
        <Route
          path="/tools"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={securityPlatform.id}
              stixCoreObjectTypes={['Tool']}
              relationshipTypes={['targets']}
              entityLink={link}
              currentView={''}
              enableContextualView={true}
              isRelationReversed={true}
            />
        }
        />
        <Route
          path="/indicators"
          element={
            <EntityStixCoreRelationshipsIndicators
              entityId={securityPlatform.id}
              entityLink={link}
            />
        }
        />
        <Route
          path="/infrastructures"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={securityPlatform.id}
              relationshipTypes={['uses', 'compromises']}
              stixCoreObjectTypes={['Infrastructure']}
              entityLink={link}
              isRelationReversed={false}
              currentView={''}
            />
        }
        />
      </Routes>
    </>
  );
};

export default SecurityPlatformKnowledgeComponent;
