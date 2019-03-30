import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityStixRelations from '../stix_relation/EntityStixRelations';
import StixDomainEntityKnowledge from '../stix_domain_entity/StixDomainEntityKnowledge';
import StixRelation from '../stix_relation/StixRelation';
import CampaignHeader from './CampaignHeader';
import CampaignKnowledgeBar from './CampaignKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRelations = [
  'incident',
  'malware',
  'attack-pattern',
  'tool',
  'vulnerability',
];

class CampaignKnowledgeComponent extends Component {
  render() {
    const { classes, campaign, location } = this.props;
    const link = `/dashboard/knowledge/campaigns/${campaign.id}/knowledge`;
    return (
      <div className={classes.container}>
        <CampaignHeader campaign={campaign} variant="noalias" />
        <CampaignKnowledgeBar campaignId={campaign.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/knowledge/campaigns/:campaignId/knowledge/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={campaign.id}
                inversedRelations={inversedRelations}
                {...routeProps}
              />
            )}
          />
          {location.pathname.includes('overview') ? (
            <StixDomainEntityKnowledge stixDomainEntityId={campaign.id} />
          ) : (
            ''
          )}

          {location.pathname.includes('attribution') ? (
            <EntityStixRelations
              entityId={campaign.id}
              relationType="attributed-to"
              targetEntityTypes={['Identity', 'Intrusion-Set']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('incidents') ? (
            <EntityStixRelations
              entityId={campaign.id}
              relationType="attributed-to"
              targetEntityTypes={['Incident']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('malwares') ? (
            <EntityStixRelations
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
              entityId={campaign.id}
              relationType="uses"
              targetEntityTypes={['Malware']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('victimology') ? (
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
            />
          ) : (
            ''
          )}

          {location.pathname.includes('ttp') ? (
            <EntityStixRelations
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
              entityId={campaign.id}
              relationType="uses"
              targetEntityTypes={['Attack-Pattern']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('tools') ? (
            <EntityStixRelations
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
              entityId={campaign.id}
              relationType="uses"
              targetEntityTypes={['Tool']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('vulnerabilities') ? (
            <EntityStixRelations
              resolveRelationType="attributed-to"
              resolveRelationRole="origin"
              entityId={campaign.id}
              relationType="targets"
              targetEntityTypes={['Vulnerability']}
              entityLink={link}
            />
          ) : (
            ''
          )}
        </div>
      </div>
    );
  }
}

CampaignKnowledgeComponent.propTypes = {
  campaign: PropTypes.object,
  classes: PropTypes.object,
  location: PropTypes.object,
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
