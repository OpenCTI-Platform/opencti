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
import ThreatActorHeader from './ThreatActorHeader';
import ThreatActorKnowledgeBar from './ThreatActorKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRoles = ['origin'];

class ThreatActorKnowledgeComponent extends Component {
  render() {
    const { classes, threatActor } = this.props;
    const link = `/dashboard/threats/threat_actors/${
      threatActor.id
    }/knowledge`;
    return (
      <div className={classes.container}>
        <ThreatActorHeader threatActor={threatActor} variant="noalias" />
        <ThreatActorKnowledgeBar threatActorId={threatActor.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/threats/threat_actors/:threatActorId/knowledge/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={threatActor.id}
                inversedRoles={inversedRoles}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/threat_actors/:threatActorId/knowledge/overview"
            render={routeProps => (
              <StixDomainEntityKnowledge
                stixDomainEntityId={threatActor.id}
                stixDomainEntityType='threat-actor'
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/threat_actors/:threatActorId/knowledge/intrusion_sets"
            render={routeProps => (
              <EntityStixRelations
                entityId={threatActor.id}
                relationType="attributed-to"
                targetEntityTypes={['Intrusion-Set']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/threat_actors/:threatActorId/knowledge/campaigns"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                resolveRelationToTypes={['Intrusion-Set']}
                entityId={threatActor.id}
                relationType="attributed-to"
                targetEntityTypes={['Campaign']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/threat_actors/:threatActorId/knowledge/incidents"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                entityId={threatActor.id}
                relationType="attributed-to"
                targetEntityTypes={['Incident']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/threat_actors/:threatActorId/knowledge/victimology"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                resolveViaTypes={[
                  {
                    entityType: 'User',
                    relationType: 'gathering',
                    relationRole: 'part_of',
                  },
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
                entityId={threatActor.id}
                relationType="targets"
                targetEntityTypes={[
                  'Organization',
                  'Sector',
                  'Country',
                  'Region',
                  'User',
                ]}
                entityLink={link}
                exploreLink={`/dashboard/explore/victimology/${threatActor.id}`}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/threat_actors/:threatActorId/knowledge/malwares"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                entityId={threatActor.id}
                relationType="uses"
                targetEntityTypes={['Malware']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/threat_actors/:threatActorId/knowledge/ttp"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                entityId={threatActor.id}
                relationType="uses"
                targetEntityTypes={['Attack-Pattern']}
                entityLink={link}
                exploreLink={`/dashboard/explore/attack_patterns/${
                  threatActor.id
                }`}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/threat_actors/:threatActorId/knowledge/tools"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                entityId={threatActor.id}
                relationType="uses"
                targetEntityTypes={['Tool']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/threat_actors/:threatActorId/knowledge/vulnerabilities"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                entityId={threatActor.id}
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

ThreatActorKnowledgeComponent.propTypes = {
  threatActor: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ThreatActorKnowledge = createFragmentContainer(
  ThreatActorKnowledgeComponent,
  {
    threatActor: graphql`
      fragment ThreatActorKnowledge_threatActor on ThreatActor {
        id
        ...ThreatActorHeader_threatActor
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ThreatActorKnowledge);
