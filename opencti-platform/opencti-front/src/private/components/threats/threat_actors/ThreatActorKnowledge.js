import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ThreatActorPopover from './ThreatActorPopover';
import ThreatActorKnowledgeBar from './ThreatActorKnowledgeBar';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectKillChain from '../../common/stix_domain_objects/StixDomainObjectKillChain';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class ThreatActorKnowledgeComponent extends Component {
  render() {
    const { classes, threatActor } = this.props;
    const link = `/dashboard/threats/threat_actors/${threatActor.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={threatActor}
          PopoverComponent={<ThreatActorPopover />}
        />
        <ThreatActorKnowledgeBar threatActorId={threatActor.id} />
        <Route
          exact
          path="/dashboard/threats/threat_actors/:threatActorId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship
              entityId={threatActor.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors/:threatActorId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={threatActor.id}
              stixDomainObjectType="threat-actor"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors/:threatActorId/knowledge/intrusion_sets"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActor.id}
              relationType="attributed-to"
              targetEntityTypes={['Intrusion-Set']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors/:threatActorId/knowledge/campaigns"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActor.id}
              relationType="attributed-to"
              targetEntityTypes={['Campaign']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors/:threatActorId/knowledge/xOpenctiIncidents"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActor.id}
              relationType="attributed-to"
              targetEntityTypes={['XOpenctiIncident']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors/:threatActorId/knowledge/victimology"
          render={(routeProps) => (
            <StixDomainObjectVictimology
              stixDomainObjectId={threatActor.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors/:threatActorId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActor.id}
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
          path="/dashboard/threats/threat_actors/:threatActorId/knowledge/ttp"
          render={(routeProps) => (
            <StixDomainObjectKillChain
              stixDomainObjectId={threatActor.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors/:threatActorId/knowledge/tools"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActor.id}
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
          path="/dashboard/threats/threat_actors/:threatActorId/knowledge/vulnerabilities"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActor.id}
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
        name
        aliases
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ThreatActorKnowledge);
