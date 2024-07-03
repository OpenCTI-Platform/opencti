import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import EntityStixCoreRelationshipsStixCyberObservable from '../../common/stix_core_relationships/views/stix_cyber_observable/EntityStixCoreRelationshipsStixCyberObservable';
import withRouter from '../../../../utils/compat-router/withRouter';

class ChannelKnowledgeComponent extends Component {
  render() {
    const { channel } = this.props;
    const link = `/dashboard/arsenal/channels/${channel.id}/knowledge`;
    return (
      <>
        <Routes>
          <Route
            path="/relations/:relationId"
            element={
              <StixCoreRelationship
                entityId={channel.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/sightings/:sightingId"
            element={
              <StixSightingRelationship
                entityId={channel.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/overview"
            element={
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={channel.id}
                stixDomainObjectName={channel.name}
                stixDomainObjectType="Channel"
              />
            }
          />
          <Route
            path="/related"
            element={
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['related-to']}
                entityLink={link}
                allDirections={true}
              />
            }
          />
          <Route
            path="/victimology"
            element={
              <StixDomainObjectVictimology
                stixDomainObjectId={channel.id}
                entityLink={link}
              />
            }
          />
          <Route
            path="/threats"
            element={
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['uses']}
                isRelationReversed={true}
                entityLink={link}
                stixCoreObjectTypes={[
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
            path="/threat_actors"
            element={
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['uses']}
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
                entityId={channel.id}
                relationshipTypes={['uses']}
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
                entityId={channel.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Campaign']}
                entityLink={link}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/attack_patterns"
            element={
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Attack-Pattern']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/channels"
            element={
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['amplifies']}
                stixCoreObjectTypes={['Channel']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/malwares"
            element={
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['uses', 'delivers', 'drops']}
                stixCoreObjectTypes={['Malware']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/vulnerabilities"
            element={
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Vulnerability']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/incidents"
            element={
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Incident']}
                entityLink={link}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/observables"
            element={
              <EntityStixCoreRelationshipsStixCyberObservable
                entityId={channel.id}
                entityLink={link}
                defaultStartTime={channel.first_seen}
                defaultStopTime={channel.last_seen}
                isRelationReversed={true}
                relationshipTypes={[
                  'related-to',
                  'publishes',
                  'uses',
                  'belongs-to',
                ]}
              />
            }
          />
          <Route
            path="/sightings"
            element={
              <EntityStixSightingRelationships
                entityId={channel.id}
                entityLink={link}
                noRightBar={true}
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

ChannelKnowledgeComponent.propTypes = {
  channel: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ChannelKnowledge = createFragmentContainer(ChannelKnowledgeComponent, {
  channel: graphql`
    fragment ChannelKnowledge_channel on Channel {
      id
      name
      aliases
    }
  `,
});

export default compose(inject18n, withRouter)(ChannelKnowledge);
