import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ThreatActorGroupPopover from './ThreatActorGroupPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class ThreatActorGroupKnowledgeComponent extends Component {
  render() {
    const { classes, threatActorGroup } = this.props;
    const link = `/dashboard/threats/threat_actors_group/${threatActorGroup.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          entityType={'Threat-Actor-Group'}
          stixDomainObject={threatActorGroup}
          PopoverComponent={<ThreatActorGroupPopover />}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship
              entityId={threatActorGroup.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/sightings/:sightingId"
          render={(routeProps) => (
            <StixSightingRelationship
              entityId={threatActorGroup.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={threatActorGroup.id}
              stixDomainObjectType="Threat-Actor"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/related"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['related-to', 'part-of']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/victimology"
          render={(routeProps) => (
            <StixDomainObjectVictimology
              stixDomainObjectId={threatActorGroup.id}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/threat_actors"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['part-of', 'cooperates-with']}
              stixCoreObjectTypes={['Threat-Actor']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/intrusion_sets"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['attributed-to']}
              stixCoreObjectTypes={['Intrusion-Set']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/campaigns"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['attributed-to', 'participates-in']}
              stixCoreObjectTypes={['Campaign']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/attack_patterns"
          render={(routeProps) => (
            <StixDomainObjectAttackPatterns
              stixDomainObjectId={threatActorGroup.id}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Malware']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/channels"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Channel']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/narratives"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Narrative']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/tools"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Tool']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/vulnerabilities"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Vulnerability']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/incidents"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['attributed-to']}
              stixCoreObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/observables"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={['Stix-Cyber-Observable']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              allDirections={true}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/infrastructures"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={threatActorGroup.id}
              relationshipTypes={['uses', 'compromises']}
              stixCoreObjectTypes={['Infrastructure']}
              entityLink={link}
              isRelationReversed={false}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge/sightings"
          render={(routeProps) => (
            <EntityStixSightingRelationships
              entityId={threatActorGroup.id}
              entityLink={link}
              noRightBar={true}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
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
              {...routeProps}
            />
          )}
        />
      </div>
    );
  }
}

ThreatActorGroupKnowledgeComponent.propTypes = {
  threatActorGroup: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ThreatActorGroupKnowledge = createFragmentContainer(
  ThreatActorGroupKnowledgeComponent,
  {
    threatActorGroup: graphql`
      fragment ThreatActorGroupKnowledge_ThreatActorGroup on ThreatActorGroup {
        id
        name
        aliases
        first_seen
        last_seen
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ThreatActorGroupKnowledge);
