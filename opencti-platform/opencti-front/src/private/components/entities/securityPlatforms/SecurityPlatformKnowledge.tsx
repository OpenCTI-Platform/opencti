/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import StixDomainObjectKnowledge from '@components/common/stix_domain_objects/StixDomainObjectKnowledge';
import StixDomainObjectAuthorKnowledge from '@components/common/stix_domain_objects/StixDomainObjectAuthorKnowledge';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
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
  relatedRelationshipTypes,
}: {
  securityPlatformData: SecurityPlatformKnowledge_SecurityPlatform$key;
  relatedRelationshipTypes: string[]
}) => {
  const securityPlatform = useFragment<SecurityPlatformKnowledge_SecurityPlatform$key>(
    securityPlatformKnowledgeFragment,
    securityPlatformData,
  );
  const location = useLocation();
  const link = `/dashboard/entities/security_platforms/${securityPlatform.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(securityPlatform.entity_type, schema);
  return (
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
        path="/sightings/:sightingId"
        element={
          <StixSightingRelationship
            entityId={securityPlatform.id}
            paddingRight={true}
          />
        }
      />
      <Route
        path="/overview"
        element={(viewAs === 'knowledge' ? (
          <StixDomainObjectKnowledge
            stixDomainObjectId={organization.id}
            stixDomainObjectType="SecurityPlatform"
          />
        ) : (
          <StixDomainObjectAuthorKnowledge
            stixDomainObjectId={organization.id}
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
            defaultStartTime={securityPlatform.startTime}
            defaultStopTime={securityPlatform.stopTime}
            allDirections
          />
        }
      />
      <Route
        path="/related"
        element={
          <EntityStixCoreRelationships
            key={location.pathname}
            entityId={securityPlatform.id}
            relationshipTypes={relatedRelationshipTypes}
            entityLink={link}
            defaultStartTime={securityPlatform.first_seen}
            defaultStopTime={securityPlatform.last_seen}
            allDirections
          />
        }
      />
      {/* <Route */}
      {/*  path="/victimology" */}
      {/*  element={ */}
      {/*    <StixDomainObjectVictimology */}
      {/*      stixDomainObjectId={securityPlatform.id} */}
      {/*      entityLink={link} */}
      {/*      defaultStartTime={securityPlatform.first_seen} */}
      {/*      defaultStopTime={securityPlatform.last_seen} */}
      {/*    /> */}
      {/*  } */}
      {/* /> */}
      {/* <Route */}
      {/*  path="/threat_actors" */}
      {/*  element={ */}
      {/*    <EntityStixCoreRelationships */}
      {/*      key={location.pathname} */}
      {/*      entityId={securityPlatform.id} */}
      {/*      relationshipTypes={[ */}
      {/*        'part-of', */}
      {/*        'cooperates-with', */}
      {/*        'employed-by', */}
      {/*        'reports-to', */}
      {/*        'supports', */}
      {/*        'derived-from', */}
      {/*      ]} */}
      {/*      stixCoreObjectTypes={['Threat-Actor']} */}
      {/*      entityLink={link} */}
      {/*      defaultStartTime={securityPlatform.first_seen} */}
      {/*      defaultStopTime={securityPlatform.last_seen} */}
      {/*      allDirections */}
      {/*    /> */}
      {/*  } */}
      {/* /> */}
      <Route
        path="/attack_patterns"
        element={
          <StixDomainObjectAttackPatterns
            stixDomainObjectId={securityPlatform.id}
            defaultStartTime={securityPlatform.first_seen}
            defaultStopTime={securityPlatform.last_seen}
          />
        }
      />
      <Route
        path="/tools"
        element={
          <EntityStixCoreRelationships
            key={location.pathname}
            entityId={securityPlatform.id}
            relationshipTypes={['uses']}
            stixCoreObjectTypes={['Tool']}
            entityLink={link}
            defaultStartTime={securityPlatform.first_seen}
            defaultStopTime={securityPlatform.last_seen}
          />
        }
      />
      <Route
        path="/organizations"
        element={
          <EntityStixCoreRelationships
            key={location.pathname}
            entityId={securityPlatform.id}
            relationshipTypes={['employed-by', 'impersonates']}
            stixCoreObjectTypes={['Organization']}
            entityLink={link}
            defaultStartTime={securityPlatform.first_seen}
            defaultStopTime={securityPlatform.last_seen}
          />
        }
      />
      <Route
        path="/indicators"
        element={
          <EntityStixCoreRelationshipsIndicators
            entityId={securityPlatform.id}
            entityLink={link}
            defaultStartTime={securityPlatform.first_seen}
            defaultStopTime={securityPlatform.last_seen}
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
            defaultStartTime={securityPlatform.first_seen}
            defaultStopTime={securityPlatform.last_seen}
          />
        }
      />
      <Route
        path="/sightings"
        element={
          <EntityStixSightingRelationships
            entityId={securityPlatform.id}
            entityLink={link}
            noRightBar={true}
            defaultStartTime={securityPlatform.first_seen}
            defaultStopTime={securityPlatform.last_seen}
            stixCoreObjectTypes={[
              'Region',
              'Country',
              'City',
              'Position',
              'Sector',
              'Organization',
              'Individual',
              'System',
            ]}
          />
        }
      />
    </Routes>
  );
};

export default SecurityPlatformKnowledgeComponent;
