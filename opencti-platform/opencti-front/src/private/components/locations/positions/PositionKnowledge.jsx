import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withRouter from '../../../../utils/compat-router/withRouter';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';

class PositionKnowledgeComponent extends Component {
  render() {
    const { position } = this.props;
    const link = `/dashboard/locations/positions/${position.id}/knowledge`;
    return (
      <>
        <Routes>
          <Route
            path="/relations/:relationId"
            element={
              <StixCoreRelationship
                entityId={position.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/sightings/:sightingId"
            element={
              <StixSightingRelationship
                entityId={position.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/overview"
            element={
              <StixDomainObjectKnowledge
                stixDomainObjectId={position.id}
                stixDomainObjectType="Position"
              />
            }
          />
          <Route
            path="/threats"
            element={
              <EntityStixCoreRelationships
                entityId={position.id}
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
                entityId={position.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={[
                  'Threat-Actor',
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
                  'Position',
                ]}
                entityLink={link}
                allDirections={true}
              />
            }
          />
          <Route
            path="/regions"
            element={
              <EntityStixCoreRelationships
                entityId={position.id}
                relationshipTypes={['located-at']}
                stixCoreObjectTypes={['Region']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/countries"
            element={
              <EntityStixCoreRelationships
                entityId={position.id}
                relationshipTypes={['located-at']}
                stixCoreObjectTypes={['Country']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/areas"
            element={
              <EntityStixCoreRelationships
                entityId={position.id}
                relationshipTypes={['located-at']}
                stixCoreObjectTypes={['Administrative-Area']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/cities"
            element={
              <EntityStixCoreRelationships
                entityId={position.id}
                relationshipTypes={['located-at']}
                stixCoreObjectTypes={['City']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/organizations"
            element={
              <EntityStixCoreRelationships
                entityId={position.id}
                relationshipTypes={['located-at']}
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
                entityId={position.id}
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
                entityId={position.id}
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
                entityId={position.id}
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
                entityId={position.id}
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
                entityId={position.id}
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
                entityId={position.id}
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
                entityId={position.id}
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
                entityId={position.id}
                relationshipTypes={['related-to', 'located-at']}
                stixCoreObjectTypes={['Stix-Cyber-Observable']}
                entityLink={link}
                allDirections={true}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/sightings"
            element={
              <EntityStixSightingRelationships
                entityId={position.id}
                entityLink={link}
                noRightBar={true}
                isTo={true}
              />
            }
          />
        </Routes>
      </>
    );
  }
}

PositionKnowledgeComponent.propTypes = {
  position: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const PositionKnowledge = createFragmentContainer(PositionKnowledgeComponent, {
  position: graphql`
    fragment PositionKnowledge_position on Position {
      id
      name
      x_opencti_aliases
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
)(PositionKnowledge);
