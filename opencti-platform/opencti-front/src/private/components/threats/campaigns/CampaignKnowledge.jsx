import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import CampaignPopover from './CampaignPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class CampaignKnowledgeComponent extends Component {
  render() {
    const { classes, campaign } = this.props;
    const link = `/dashboard/threats/campaigns/${campaign.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          entityType={'Campaign'}
          stixDomainObject={campaign}
          PopoverComponent={<CampaignPopover />}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={campaign.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={campaign.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={campaign.id}
                stixDomainObjectType="Campaign"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={[
                  'Threat-Actor-Group',
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
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/attribution"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['attributed-to']}
                stixCoreObjectTypes={['Threat-Actor-Group', 'Intrusion-Set']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/victimology"
            render={(routeProps) => (
              <StixDomainObjectVictimology
                stixDomainObjectId={campaign.id}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/attack_patterns"
            render={(routeProps) => (
              <StixDomainObjectAttackPatterns
                stixDomainObjectId={campaign.id}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Malware']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Tool']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/channels"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Channel']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/narratives"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Narrative']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/vulnerabilities"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Vulnerability']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['attributed-to']}
                stixCoreObjectTypes={['Incident']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/observables"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={['Stix-Cyber-Observable']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                allDirections={true}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/infrastructures"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={campaign.id}
                relationshipTypes={['uses', 'compromises']}
                stixCoreObjectTypes={['Infrastructure']}
                entityLink={link}
                defaultStartTime={campaign.first_seen}
                defaultStopTime={campaign.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/campaigns/:campaignId/knowledge/sightings"
            render={(routeProps) => (
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
                {...routeProps}
              />
            )}
          />
        </Switch>
      </div>
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

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CampaignKnowledge);
