import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAuthorKnowledge from '../../common/stix_domain_objects/StixDomainObjectAuthorKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import withRouter from '../../../../utils/compat-router/withRouter';

class IndividualKnowledgeComponent extends Component {
  render() {
    const { individual, viewAs } = this.props;
    const link = `/dashboard/entities/individuals/${individual.id}/knowledge`;
    return (
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship
              entityId={individual.id}
              paddingRight={true}
            />
          }
        />
        <Route
          path="/sightings/:sightingId"
          element={
            <StixSightingRelationship
              entityId={individual.id}
              paddingRight={true}
            />
          }
        />
        <Route
          path="/overview"
          element={(viewAs === 'knowledge' ? (
            <StixDomainObjectKnowledge
              stixDomainObjectId={individual.id}
              stixDomainObjectType="Individual"
            />
          ) : (
            <StixDomainObjectAuthorKnowledge
              stixDomainObjectId={individual.id}
              stixDomainObjectType="Individual"
            />
          ))
            }
        />
        <Route
          path="/threats"
          element={
            <EntityStixCoreRelationships
              entityId={individual.id}
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
              entityId={individual.id}
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
              entityId={individual.id}
              relationshipTypes={['part-of']}
              stixCoreObjectTypes={['Organization']}
              entityLink={link}
              isRelationReversed={false}
            />
          }
        />
        <Route
          path="/locations"
          element={
            <EntityStixCoreRelationships
              entityId={individual.id}
              relationshipTypes={['located-at']}
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
              entityId={individual.id}
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
              entityId={individual.id}
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
              entityId={individual.id}
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
              entityId={individual.id}
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
              entityId={individual.id}
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
              entityId={individual.id}
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
              entityId={individual.id}
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
              entityId={individual.id}
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

IndividualKnowledgeComponent.propTypes = {
  individual: PropTypes.object,
  viewAs: PropTypes.string,
};

const IndividualKnowledge = createFragmentContainer(
  IndividualKnowledgeComponent,
  {
    individual: graphql`
      fragment IndividualKnowledge_individual on Individual {
        id
        name
        x_opencti_aliases
      }
    `,
  },
);

export default withRouter(IndividualKnowledge);
