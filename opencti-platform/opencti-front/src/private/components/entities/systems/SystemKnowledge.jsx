import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import withRouter from '../../../../utils/compat-router/withRouter';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectAuthorKnowledge from '../../common/stix_domain_objects/StixDomainObjectAuthorKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

class SystemKnowledgeComponent extends Component {
  render() {
    const { system, viewAs } = this.props;
    const link = `/dashboard/entities/systems/${system.id}/knowledge`;
    return (
      <>
        <Routes>
          <Route
            path="/relations/:relationId"
            element={
              <StixCoreRelationship
                entityId={system.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/sightings/:sightingId"
            element={
              <StixSightingRelationship
                entityId={system.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/overview"
            element={(viewAs === 'knowledge' ? (
              <StixDomainObjectKnowledge
                stixDomainObjectId={system.id}
                stixDomainObjectType="System"
              />
            ) : (
              <StixDomainObjectAuthorKnowledge
                stixDomainObjectId={system.id}
                stixDomainObjectType="System"
              />
            ))
            }
          />
          <Route
            path="/threats"
            element={
              <EntityStixCoreRelationships
                entityId={system.id}
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
                entityId={system.id}
                relationshipTypes={['related-to']}
                entityLink={link}
                allDirections={true}
              />
            }
          />
          <Route
            path="/systems"
            element={
              <EntityStixCoreRelationships
                entityId={system.id}
                relationshipTypes={['part-of']}
                stixCoreObjectTypes={['System']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/locations"
            element={
              <EntityStixCoreRelationships
                entityId={system.id}
                relationshipTypes={['localization']}
                stixCoreObjectTypes={['City', 'Country', 'Region']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/threat_actors"
            element={
              <EntityStixCoreRelationships
                entityId={system.id}
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
                entityId={system.id}
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
                entityId={system.id}
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
                entityId={system.id}
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
                entityId={system.id}
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
                entityId={system.id}
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
                entityId={system.id}
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
                entityId={system.id}
                relationshipTypes={['related-to']}
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
                entityId={system.id}
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

SystemKnowledgeComponent.propTypes = {
  system: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
};

const SystemKnowledge = createFragmentContainer(SystemKnowledgeComponent, {
  system: graphql`
    fragment SystemKnowledge_system on System {
      id
      name
      x_opencti_aliases
    }
  `,
});

export default withRouter(SystemKnowledge);
