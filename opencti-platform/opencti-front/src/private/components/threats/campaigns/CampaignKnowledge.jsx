import React, { Component } from 'react';
import PropTypes from 'prop-types';
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

class CampaignKnowledgeComponent extends Component {
  render() {
    const { campaign } = this.props;
    const link = `/dashboard/threats/campaigns/${campaign.id}/knowledge`;
    return (
      <>
        <Routes>
          <Route
            path="/relations/:relationId"
            element={
              <StixCoreRelationship
                entityId={campaign.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/sightings/:sightingId"
            element={
              <StixSightingRelationship
                entityId={campaign.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/overview"
            element={
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={campaign.id}
                stixDomainObjectName={campaign.name}
                stixDomainObjectType="Campaign"
              />
            }
          />
          <Route
            path="/related"
            element={
              <EntityStixCoreRelationships
                entityId={campaign.id}
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
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                allDirections={true}
              />
            }
          />
          <Route
            path="/attribution"
            element={
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['attributed-to', 'participates-in']}
                stixCoreObjectTypes={['Threat-Actor', 'Intrusion-Set']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/victimology"
            element={
              <StixDomainObjectVictimology
                stixDomainObjectId={campaign.id}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
              />
            }
          />
          <Route
            path="/attack_patterns"
            element={
              <StixDomainObjectAttackPatterns
                stixDomainObjectId={campaign.id}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
              />
            }
          />
          <Route
            path="/malwares"
            element={
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Malware']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/tools"
            element={
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Tool']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/channels"
            element={
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Channel']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/narratives"
            element={
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Narrative']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/vulnerabilities"
            element={
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Vulnerability']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/incidents"
            element={
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['attributed-to']}
                stixCoreObjectTypes={['Incident']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/indicators"
            element={
              <EntityStixCoreRelationshipsIndicators
                entityId={campaign.id}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
              />
            }
          />
          <Route
            path="/observables"
            element={
              <EntityStixCoreRelationshipsStixCyberObservable
                entityId={campaign.id}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={true}
                relationshipTypes={['related-to']}
              />
            }
          />
          <Route
            path="/infrastructures"
            element={
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['uses', 'compromises']}
                stixCoreObjectTypes={['Infrastructure']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/sightings"
            element={
              <EntityStixSightingRelationships
                entityId={campaign.id}
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
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
              />
            }
          />
        </Routes>
      </>
    );
  }
}

CampaignKnowledgeComponent.propTypes = {
  campaign: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CampaignKnowledge = createFragmentContainer(CampaignKnowledgeComponent, {
  campaign: graphql`
    fragment CampaignKnowledge_campaign on Campaign {
      id
      name
      aliases
      first_seen
      last_seen
    }
  `,
});

export default withRouter(CampaignKnowledge);
