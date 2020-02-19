import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixRelations from '../../common/stix_relations/EntityStixRelations';
import StixDomainEntityThreatKnowledge from '../../common/stix_domain_entities/StixDomainEntityThreatKnowledge';
import StixRelation from '../../common/stix_relations/StixRelation';
import CampaignPopover from './CampaignPopover';
import CampaignKnowledgeBar from './CampaignKnowledgeBar';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import StixDomainEntityKillChain from '../../common/stix_domain_entities/StixDomainEntityKillChain';
import StixDomainEntityVictimology from '../../common/stix_domain_entities/StixDomainEntityVictimology';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class CampaignKnowledgeComponent extends Component {
  render() {
    const { classes, campaign } = this.props;
    const link = `/dashboard/threats/campaigns/${campaign.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={campaign}
          PopoverComponent={<CampaignPopover />}
        />
        <CampaignKnowledgeBar campaignId={campaign.id} />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
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
            <StixDomainEntityThreatKnowledge
              stixDomainEntityId={campaign.id}
              stixDomainEntityType="campaign"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/attribution"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={campaign.id}
              relationType="attributed-to"
              targetEntityTypes={['Identity', 'Intrusion-Set']}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/incidents"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={campaign.id}
              relationType="attributed-to"
              targetEntityTypes={['Incident']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={campaign.id}
              relationType="uses"
              targetEntityTypes={['Malware']}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/victimology"
          render={(routeProps) => (
            <StixDomainEntityVictimology
              stixDomainEntityId={campaign.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/ttp"
          render={(routeProps) => (
            <StixDomainEntityKillChain
              stixDomainEntityId={campaign.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/tools"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={campaign.id}
              relationType="uses"
              targetEntityTypes={['Tool']}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/vulnerabilities"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={campaign.id}
              relationType="targets"
              targetEntityTypes={['Vulnerability']}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
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
      alias
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CampaignKnowledge);
