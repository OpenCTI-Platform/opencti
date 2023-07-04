import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import IntrusionSetPopover from './IntrusionSetPopover';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
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

class IntrusionSetKnowledgeComponent extends Component {
  render() {
    const { classes, intrusionSet } = this.props;
    const link = `/dashboard/threats/intrusion_sets/${intrusionSet.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          entityType={'Intrusion-Set'}
          stixDomainObject={intrusionSet}
          PopoverComponent={<IntrusionSetPopover />}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={intrusionSet.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={intrusionSet.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={intrusionSet.id}
                stixDomainObjectType="Intrusion-Set"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['related-to']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                allDirections={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/attribution"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['attributed-to']}
                stixCoreObjectTypes={['Theat-Actor-Group']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/victimology"
            render={(routeProps) => (
              <StixDomainObjectVictimology
                stixDomainObjectId={intrusionSet.id}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['attributed-to']}
                stixCoreObjectTypes={['Campaign']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/attack_patterns"
            render={(routeProps) => (
              <StixDomainObjectAttackPatterns
                stixDomainObjectId={intrusionSet.id}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Malware']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Tool']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/channels"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Channel']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/narratives"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Narrative']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/vulnerabilities"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Vulnerability']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['attributed-to']}
                stixCoreObjectTypes={['Incident']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/observables"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={['Stix-Cyber-Observable']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                allDirections={true}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/infrastructures"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={intrusionSet.id}
                relationshipTypes={['uses', 'compromises']}
                stixCoreObjectTypes={['Infrastructure']}
                entityLink={link}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge/sightings"
            render={(routeProps) => (
              <EntityStixSightingRelationships
                entityId={intrusionSet.id}
                entityLink={link}
                noRightBar={true}
                defaultStartTime={intrusionSet.first_seen}
                defaultStopTime={intrusionSet.last_seen}
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
        </Switch>
      </div>
    );
  }
}

IntrusionSetKnowledgeComponent.propTypes = {
  intrusionSet: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const IntrusionSetKnowledge = createFragmentContainer(
  IntrusionSetKnowledgeComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetKnowledge_intrusionSet on IntrusionSet {
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
)(IntrusionSetKnowledge);
