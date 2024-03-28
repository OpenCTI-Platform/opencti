import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, Routes } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAuthorKnowledge from '../../common/stix_domain_objects/StixDomainObjectAuthorKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import withRouter from '../../../../utils/compat-router/withRouter';

class OrganizationKnowledgeComponent extends Component {
  render() {
    const { organization, viewAs } = this.props;
    const link = `/dashboard/entities/organizations/${organization.id}/knowledge`;
    return (
      <Routes>
        <Route
          path="/relations/:relationId/*"
          element={
            <StixCoreRelationship
              entityId={organization.id}
              paddingRight={true}
            />
          }
        />
        <Route
          path="/sightings/:sightingId"
          element={
            <StixSightingRelationship
              entityId={organization.id}
              paddingRight={true}
            />
          }
        />
        <Route
          path="/overview"
          element={(viewAs === 'knowledge' ? (
            <StixDomainObjectKnowledge
              stixDomainObjectId={organization.id}
              stixDomainObjectType="Organization"
            />
          ) : (
            <StixDomainObjectAuthorKnowledge
              stixDomainObjectId={organization.id}
              stixDomainObjectType="Organization"
            />
          ))
            }
        />
        <Route
          path="/threats"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['targets']}
              isRelationReversed
              entityLink={link}
              stixCoreObjectTypes={[
                'Attack-Pattern',
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Incident',
                'Malware',
                'Tool',
              ]}
            />
          }
        />
        <Route
          path="/related"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['related-to']}
              entityLink={link}
              allDirections={true}
            />
          }
        />
        <Route
          path="/organizations"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['part-of']}
              role="part-of_to"
              stixCoreObjectTypes={['Organization']}
              entityLink={link}
              isRelationReversed={false}
            />
          }
        />
        <Route
          path="/individuals"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['part-of']}
              stixCoreObjectTypes={['Individual']}
              entityLink={link}
              isRelationReversed={true}
            />
          }
        />
        <Route
          path="/locations"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Location']}
              entityLink={link}
              isRelationReversed={false}
            />
          }
        />
        <Route
          path="/sectors"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['part-of']}
              stixCoreObjectTypes={['Sector']}
              entityLink={link}
              isRelationReversed={false}
            />
          }
        />
        <Route
          path="/used_tools"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Tool']}
              entityLink={link}
              isRelationReversed={false}
            />
          }
        />
        <Route
          path="/threat_actors"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['targets', 'employed-by']}
              stixCoreObjectTypes={['Threat-Actor']}
              entityLink={link}
              isRelationReversed={true}
            />
          }
        />
        <Route
          path="/intrusion_sets"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Intrusion-Set']}
              entityLink={link}
              isRelationReversed={true}
            />
          }
        />
        <Route
          path="/campaigns"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Campaign']}
              entityLink={link}
              isRelationReversed={true}
            />
          }
        />
        <Route
          path="/incidents"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
            />
          }
        />
        <Route
          path="/malwares"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Malware']}
              entityLink={link}
              isRelationReversed={true}
            />
          }
        />
        <Route
          path="/attack_patterns"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Attack-Pattern']}
              entityLink={link}
              isRelationReversed={true}
            />
          }
        />
        <Route
          path="/tools"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Tool']}
              entityLink={link}
              isRelationReversed={true}
            />
          }
        />
        <Route
          path="/vulnerabilities"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={['Vulnerability']}
              entityLink={link}
              allDirections={true}
            />
          }
        />
        <Route
          path="/observables"
          element={
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={['Stix-Cyber-Observable']}
              entityLink={link}
              allDirections={true}
              isRelationReversed={true}
            />
          }
        />
      </Routes>
    );
  }
}

OrganizationKnowledgeComponent.propTypes = {
  organization: PropTypes.object,
  viewAs: PropTypes.string,
};

const OrganizationKnowledge = createFragmentContainer(
  OrganizationKnowledgeComponent,
  {
    organization: graphql`
      fragment OrganizationKnowledge_organization on Organization {
        id
        name
        x_opencti_aliases
      }
    `,
  },
);

export default withRouter(OrganizationKnowledge);
