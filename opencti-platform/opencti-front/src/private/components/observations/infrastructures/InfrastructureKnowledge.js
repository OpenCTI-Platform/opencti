import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import InfrastructurePopover from './InfrastructurePopover';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import StixCoreObjectStixCyberObservables from '../stix_cyber_observables/StixCoreObjectStixCyberObservables';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class InfrastructureKnowledgeComponent extends Component {
  render() {
    const { classes, infrastructure } = this.props;
    const link = `/dashboard/observations/infrastructures/${infrastructure.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={infrastructure}
          PopoverComponent={<InfrastructurePopover />}
        />
        <StixCoreObjectKnowledgeBar
          stixCoreObjectLink={link}
          availableSections={[
            'intrusion_sets',
            'campaigns',
            'incidents',
            'malwares',
            'tools',
            'vulnerabilities',
            'observables',
            'observed_data',
            'sightings',
          ]}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship
              entityId={infrastructure.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/sightings/:sightingId"
          render={(routeProps) => (
            <StixSightingRelationship
              entityId={infrastructure.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={infrastructure.id}
              stixDomainObjectType="Intrusion-Set"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/related"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={infrastructure.id}
              relationshipTypes={['related-to']}
              targetStixDomainObjectTypes={[
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
              defaultStartTime={infrastructure.first_seen}
              defaultStopTime={infrastructure.last_seen}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/observables"
          render={(routeProps) => (
            <StixCoreObjectStixCyberObservables
              stixCoreObjectId={infrastructure.id}
              stixCoreObjectLink={link}
              defaultStartTime={infrastructure.first_seen}
              defaultStopTime={infrastructure.last_seen}
              noRightBar={true}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/observed_data"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={infrastructure.id}
              targetStixDomainObjectTypes={['Observed-Data']}
              relationshipTypes={['consists-of']}
              entityLink={link}
              defaultStartTime={infrastructure.first_seen}
              defaultStopTime={infrastructure.last_seen}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/intrusion_sets"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={infrastructure.id}
              targetStixDomainObjectTypes={['Intrusion-Set']}
              entityLink={link}
              defaultStartTime={infrastructure.first_seen}
              defaultStopTime={infrastructure.last_seen}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/campaigns"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={infrastructure.id}
              targetStixDomainObjectTypes={['Campaign']}
              entityLink={link}
              defaultStartTime={infrastructure.first_seen}
              defaultStopTime={infrastructure.last_seen}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={infrastructure.id}
              targetStixDomainObjectTypes={['Malware']}
              entityLink={link}
              defaultStartTime={infrastructure.first_seen}
              defaultStopTime={infrastructure.last_seen}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/tools"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={infrastructure.id}
              targetStixDomainObjectTypes={['Tool']}
              entityLink={link}
              defaultStartTime={infrastructure.first_seen}
              defaultStopTime={infrastructure.last_seen}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/vulnerabilities"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={infrastructure.id}
              relationshipTypes={['has']}
              targetStixDomainObjectTypes={['Vulnerability']}
              entityLink={link}
              defaultStartTime={infrastructure.first_seen}
              defaultStopTime={infrastructure.last_seen}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/sightings"
          render={(routeProps) => (
            <EntityStixSightingRelationships
              entityId={infrastructure.id}
              entityLink={link}
              noRightBar={true}
              targetStixDomainObjectTypes={[
                'Region',
                'Country',
                'City',
                'Position',
                'Sector',
                'Organization',
                'Individual',
                'System',
              ]}
              defaultStartTime={infrastructure.first_seen}
              defaultStopTime={infrastructure.last_seen}
              {...routeProps}
            />
          )}
        />
      </div>
    );
  }
}

InfrastructureKnowledgeComponent.propTypes = {
  infrastructure: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const InfrastructureKnowledge = createFragmentContainer(
  InfrastructureKnowledgeComponent,
  {
    infrastructure: graphql`
      fragment InfrastructureKnowledge_infrastructure on Infrastructure {
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
)(InfrastructureKnowledge);
