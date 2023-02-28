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
import DevicePopover from './DevicePopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import StixCoreObjectStixCyberObservables from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class DeviceKnowledgeComponent extends Component {
  render() {
    const { classes, device } = this.props;
    const link = `/defender_hq/assets/devices/${device.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={device}
          PopoverComponent={<DevicePopover />}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship
              entityId={device.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/sightings/:sightingId"
          render={(routeProps) => (
            <StixSightingRelationship
              entityId={device.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={device.id}
              stixDomainObjectType="Device"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/related"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={device.id}
              relationshipTypes={['related-to', 'part-of']}
              targetStixDomainObjectTypes={[
                'Device',
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
              allDirections={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/victimology"
          render={(routeProps) => (
            <StixDomainObjectVictimology
              stixDomainObjectId={device.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/devices"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={device.id}
              relationshipTypes={['part-of']}
              targetStixDomainObjectTypes={['Device']}
              entityLink={link}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/network"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={device.id}
              relationshipTypes={['attributed-to']}
              targetStixDomainObjectTypes={['Intrusion-Set']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/software"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={device.id}
              relationshipTypes={['attributed-to']}
              targetStixDomainObjectTypes={['Software']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/attack_patterns"
          render={(routeProps) => (
            <StixDomainObjectAttackPatterns
              stixDomainObjectId={device.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={device.id}
              relationshipTypes={['uses']}
              targetStixDomainObjectTypes={['Malware']}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/tools"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={device.id}
              relationshipTypes={['uses']}
              targetStixDomainObjectTypes={['Tool']}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/vulnerabilities"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={device.id}
              relationshipTypes={['targets']}
              targetStixDomainObjectTypes={['Vulnerability']}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/incidents"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={device.id}
              relationshipTypes={['attributed-to']}
              targetStixDomainObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/observables"
          render={(routeProps) => (
            <StixCoreObjectStixCyberObservables
              stixCoreObjectId={device.id}
              stixCoreObjectLink={link}
              noRightBar={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/infrastructures"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={device.id}
              relationshipTypes={['uses', 'compromises']}
              targetStixDomainObjectTypes={['Infrastructure']}
              entityLink={link}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/defender_hq/assets/devices/:deviceId/knowledge/sightings"
          render={(routeProps) => (
            <EntityStixSightingRelationships
              entityId={device.id}
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
              {...routeProps}
            />
          )}
        />
      </div>
    );
  }
}

DeviceKnowledgeComponent.propTypes = {
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const DeviceKnowledge = createFragmentContainer(
  DeviceKnowledgeComponent,
  {
    device: graphql`
      fragment DeviceKnowledge_device on ThreatActor {
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
)(DeviceKnowledge);
