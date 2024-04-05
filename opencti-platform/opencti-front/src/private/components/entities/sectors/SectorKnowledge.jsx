import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, Routes } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import withRouter from '../../../../utils/compat-router/withRouter';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

class SectorKnowledgeComponent extends Component {
  render() {
    const { sector } = this.props;
    const link = `/dashboard/entities/sectors/${sector.id}/knowledge`;
    return (
      <>
        <Routes>
          <Route
            path="/relations/:relationId/*"
            element={
              <StixCoreRelationship
                entityId={sector.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/sightings/:sightingId/*"
            element={
              <StixSightingRelationship
                entityId={sector.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/overview"
            element={
              <StixDomainObjectKnowledge
                stixDomainObjectId={sector.id}
                stixDomainObjectType="Sector"
              />
            }
          />
          <Route
            path="/threats"
            element={
              <EntityStixCoreRelationships
                entityId={sector.id}
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
                entityId={sector.id}
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
                entityId={sector.id}
                relationshipTypes={['part-of']}
                stixCoreObjectTypes={['Organization']}
                entityLink={link}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/threat_actors"
            element={
              <EntityStixCoreRelationships
                entityId={sector.id}
                relationshipTypes={['targets']}
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
                entityId={sector.id}
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
                entityId={sector.id}
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
                entityId={sector.id}
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
                entityId={sector.id}
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
                entityId={sector.id}
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
                entityId={sector.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Tool']}
                entityLink={link}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/observables"
            element={
              <EntityStixCoreRelationships
                entityId={sector.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={['Stix-Cyber-Observable']}
                entityLink={link}
                allDirections={true}
                isRelationReversed={true}
              />
            }
          />
        </Routes>
      </>
    );
  }
}

SectorKnowledgeComponent.propTypes = {
  sector: PropTypes.object,
};

const SectorKnowledge = createFragmentContainer(SectorKnowledgeComponent, {
  sector: graphql`
    fragment SectorKnowledge_sector on Sector {
      id
      name
      x_opencti_aliases
    }
  `,
});

export default withRouter(SectorKnowledge);
