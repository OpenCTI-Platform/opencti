import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import withRouter from '../../../../utils/compat-router/withRouter';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import EntityStixCoreRelationshipsIndicators from '../../common/stix_core_relationships/views/indicators/EntityStixCoreRelationshipsIndicators';
import EntityStixCoreRelationshipsStixCyberObservable from '../../common/stix_core_relationships/views/stix_cyber_observable/EntityStixCoreRelationshipsStixCyberObservable';

class IntrusionSetKnowledgeComponent extends Component {
  render() {
    const { intrusionSet } = this.props;
    const link = `/dashboard/threats/intrusion_sets/${intrusionSet.id}/knowledge`;
    return (
      <>
        <Routes>
          <Route
            path="/relations/:relationId"
            element={
              <StixCoreRelationship
                entityId={intrusionSet.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/sightings/:sightingId"
            element={
              <StixSightingRelationship
                entityId={intrusionSet.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/overview"
            element={
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={intrusionSet.id}
                stixDomainObjectName={intrusionSet.name}
                stixDomainObjectType="Intrusion-Set"
              />
            }
          />
          <Route
            path="/related"
            element={
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['related-to']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                allDirections={true}
              />
            }
          />
          <Route
            path="/attribution"
            element={
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['attributed-to']}
                stixCoreObjectTypes={['Threat-Actor']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/victimology"
            element={
              <StixDomainObjectVictimology
                stixDomainObjectId={intrusionSet.id}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
              />
            }
          />
          <Route
            path="/campaigns"
            element={
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['attributed-to']}
                stixCoreObjectTypes={['Campaign']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/attack_patterns"
            element={
              <StixDomainObjectAttackPatterns
                stixDomainObjectId={intrusionSet.id}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
              />
            }
          />
          <Route
            path="/malwares"
            element={
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Malware']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/tools"
            element={
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Tool']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/channels"
            element={
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Channel']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/narratives"
            element={
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Narrative']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/vulnerabilities"
            element={
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Vulnerability']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/incidents"
            element={
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['attributed-to']}
                stixCoreObjectTypes={['Incident']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/indicators"
            element={
              <EntityStixCoreRelationshipsIndicators
                entityId={intrusionSet.id}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
              />
            }
          />
          <Route
            path="/observables"
            element={
              <EntityStixCoreRelationshipsStixCyberObservable
                entityId={intrusionSet.id}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={true}
                relationshipTypes={['related-to']}
              />
            }
          />
          <Route
            path="/infrastructures"
            element={
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['uses', 'compromises']}
                stixCoreObjectTypes={['Infrastructure']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/sightings"
            element={
              <EntityStixSightingRelationships
                entityId={intrusionSet.id}
                entityLink={link}
                noRightBar={true}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
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
      </>
    );
  }
}

IntrusionSetKnowledgeComponent.propTypes = {
  intrusionSet: PropTypes.object,
  t: PropTypes.func,
};

const IntrusionSetKnowledge = createFragmentContainer(
  IntrusionSetKnowledgeComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetKnowledge_intrusionSet on IntrusionSet {
        id
        name
        aliases
        first_seen
        last_seen
      }
    `,
  },
);

export default withRouter(IntrusionSetKnowledge);
