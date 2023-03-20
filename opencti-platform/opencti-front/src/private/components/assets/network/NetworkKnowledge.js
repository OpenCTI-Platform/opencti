import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import NetworkPopover from './NetworkPopover';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
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

class NetworkKnowledgeComponent extends Component {
  render() {
    const { classes, network } = this.props;
    const link = `/defender_hq/assets/network/${network.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={network}
          PopoverComponent={<NetworkPopover />}
        />
        <Switch>
          <Route
            exact
            path="/defender_hq/assets/network/:networkId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={network.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/network/:networkId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={network.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/network/:networkId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={network.id}
                stixDomainObjectType="Network"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/network/:networkId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={network.id}
                relationshipTypes={['related-to']}
                targetStixDomainObjectTypes={[
                  'Device',
                  'Network',
                  'Software',
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
            path="/defender_hq/assets/network/:networkId/knowledge/attribution"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={network.id}
                relationshipTypes={['attributed-to']}
                targetStixDomainObjectTypes={['Device']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/network/:networkId/knowledge/victimology"
            render={(routeProps) => (
              <StixDomainObjectVictimology
                stixDomainObjectId={network.id}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/network/:networkId/knowledge/software"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={network.id}
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
            path="/defender_hq/assets/network/:networkId/knowledge/attack_patterns"
            render={(routeProps) => (
              <StixDomainObjectAttackPatterns
                stixDomainObjectId={network.id}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/network/:networkId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={network.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Malware']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/network/:networkId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={network.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Tool']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/network/:networkId/knowledge/vulnerabilities"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={network.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Vulnerability']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/network/:networkId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={network.id}
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
            path="/defender_hq/assets/network/:networkId/knowledge/observables"
            render={(routeProps) => (
              <StixCoreObjectStixCyberObservables
                stixCoreObjectId={network.id}
                stixCoreObjectLink={link}
                noRightBar={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/network/:networkId/knowledge/infrastructures"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={network.id}
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
            path="/defender_hq/assets/network/:networkId/knowledge/sightings"
            render={(routeProps) => (
              <EntityStixSightingRelationships
                entityId={network.id}
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
        </Switch>
      </div>
    );
  }
}

NetworkKnowledgeComponent.propTypes = {
  network: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const NetworkKnowledge = createFragmentContainer(
  NetworkKnowledgeComponent,
  {
    network: graphql`
      fragment NetworkKnowledge_network on IntrusionSet {
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
)(NetworkKnowledge);
