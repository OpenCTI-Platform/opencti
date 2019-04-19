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
import IncidentHeader from './IncidentHeader';
import IncidentKnowledgeBar from './IncidentKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRelations = [];

class IncidentKnowledgeComponent extends Component {
  render() {
    const { classes, incident } = this.props;
    const link = `/dashboard/knowledge/incidents/${incident.id}/knowledge`;
    return (
      <div className={classes.container}>
        <IncidentHeader incident={incident} variant="noalias" />
        <IncidentKnowledgeBar incidentId={incident.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/knowledge/incidents/:incidentId/knowledge/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={incident.id}
                inversedRelations={inversedRelations}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/incidents/:incidentId/knowledge/overview"
            render={routeProps => (
              <StixDomainEntityKnowledge
                stixDomainEntityId={incident.id}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/incidents/:incidentId/knowledge/attribution"
            render={routeProps => (
              <EntityStixRelations
                entityId={incident.id}
                relationType="attributed-to"
                targetEntityTypes={[
                  'Threat-Actor',
                  'Intrusion-Set',
                  'Campaign',
                ]}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/incidents/:incidentId/knowledge/malwares"
            render={routeProps => (
              <EntityStixRelations
                entityId={incident.id}
                relationType="uses"
                targetEntityTypes={['Malware']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/incidents/:incidentId/knowledge/victimology"
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
                entityId={incident.id}
                relationType="targets"
                targetEntityTypes={[
                  'Organization',
                  'Sector',
                  'Country',
                  'Region',
                ]}
                entityLink={link}
                exploreLink={`/dashboard/explore/victimology/${incident.id}`}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/incidents/:incidentId/knowledge/ttp"
            render={routeProps => (
              <EntityStixRelations
                entityId={incident.id}
                relationType="uses"
                targetEntityTypes={['Attack-Pattern']}
                entityLink={link}
                exploreLink={`/dashboard/explore/attack_patterns/${incident.id}`}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/incidents/:incidentId/knowledge/tools"
            render={routeProps => (
              <EntityStixRelations
                entityId={incident.id}
                relationType="uses"
                targetEntityTypes={['Tool']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/incidents/:incidentId/knowledge/vulnerabilities"
            render={routeProps => (
              <EntityStixRelations
                entityId={incident.id}
                relationType="targets"
                targetEntityTypes={['Vulnerability']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
        </div>
      </div>
    );
  }
}

IncidentKnowledgeComponent.propTypes = {
  incident: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const IncidentKnowledge = createFragmentContainer(IncidentKnowledgeComponent, {
  incident: graphql`
    fragment IncidentKnowledge_incident on Incident {
      id
      ...IncidentHeader_incident
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(IncidentKnowledge);
