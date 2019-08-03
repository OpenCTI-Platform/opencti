import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixRelations from '../../common/stix_relations/EntityStixRelations';
import StixDomainEntityKnowledge from '../../common/stix_domain_entities/StixDomainEntityKnowledge';
import StixRelation from '../../common/stix_relations/StixRelation';
import CampaignHeader from './CampaignHeader';
import CampaignKnowledgeBar from './CampaignKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

const inversedRoles = ['origin'];

class CampaignKnowledgeComponent extends Component {
  render() {
    const { classes, campaign } = this.props;
    const link = `/dashboard/threats/campaigns/${campaign.id}/knowledge`;
    return (
      <div className={classes.container}>
        <CampaignHeader campaign={campaign} />
        <CampaignKnowledgeBar campaignId={campaign.id} />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/relations/:relationId"
          render={routeProps => (
            <StixRelation
              entityId={campaign.id}
              inversedRoles={inversedRoles}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/overview"
          render={routeProps => (
            <StixDomainEntityKnowledge
              stixDomainEntityId={campaign.id}
              stixDomainEntityType="campaign"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/attribution"
          render={routeProps => (
            <EntityStixRelations
              entityId={campaign.id}
              relationType="attributed-to"
              targetEntityTypes={['Identity', 'Intrusion-Set']}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/incidents"
          render={routeProps => (
            <EntityStixRelations
              entityId={campaign.id}
              relationType="attributed-to"
              targetEntityTypes={['Incident']}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/malwares"
          render={routeProps => (
            <EntityStixRelations
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
              entityId={campaign.id}
              relationType="uses"
              targetEntityTypes={['Malware']}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/victimology"
          render={routeProps => (
            <EntityStixRelations
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
              resolveViaTypes={[
                {
                  entityType: 'Organization',
                  relationType: 'gathering',
                  relationRole: 'part_of',
                },
                {
                  entityType: 'Organization',
                  relationType: 'localization',
                  relationRole: 'localized',
                },
                {
                  entityType: 'Country',
                  relationType: 'localization',
                  relationRole: 'localized',
                },
              ]}
              entityId={campaign.id}
              relationType="targets"
              targetEntityTypes={[
                'Organization',
                'Sector',
                'Country',
                'Region',
              ]}
              entityLink={link}
              exploreLink={`/dashboard/explore/victimology/${campaign.id}`}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/ttp"
          render={routeProps => (
            <EntityStixRelations
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
              entityId={campaign.id}
              relationType="uses"
              targetEntityTypes={['Attack-Pattern']}
              entityLink={link}
              exploreLink={`/dashboard/explore/attack_patterns/${campaign.id}`}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/tools"
          render={routeProps => (
            <EntityStixRelations
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
              entityId={campaign.id}
              relationType="uses"
              targetEntityTypes={['Tool']}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/knowledge/vulnerabilities"
          render={routeProps => (
            <EntityStixRelations
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
              entityId={campaign.id}
              relationType="targets"
              targetEntityTypes={['Vulnerability']}
              entityLink={link}
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
      ...CampaignHeader_campaign
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CampaignKnowledge);
