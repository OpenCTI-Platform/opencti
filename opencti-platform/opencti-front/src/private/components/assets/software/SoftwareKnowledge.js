import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import SoftwarePopover from './SoftwarePopover';
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

class SoftwareKnowledgeComponent extends Component {
  render() {
    const { classes, software } = this.props;
    const link = `/defender_hq/assets/software/${software.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={software}
          PopoverComponent={<SoftwarePopover />}
        />
        <Switch>
          <Route
            exact
            path="/defender_hq/assets/software/:softwareId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={software.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/software/:softwareId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={software.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/software/:softwareId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={software.id}
                stixDomainObjectType="Software"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/software/:softwareId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={software.id}
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
            path="/defender_hq/assets/software/:softwareId/knowledge/attribution"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={software.id}
                relationshipTypes={['attributed-to']}
                targetStixDomainObjectTypes={['Device', 'Network']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/software/:softwareId/knowledge/victimology"
            render={(routeProps) => (
              <StixDomainObjectVictimology
                stixDomainObjectId={software.id}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/software/:softwareId/knowledge/attack_patterns"
            render={(routeProps) => (
              <StixDomainObjectAttackPatterns
                stixDomainObjectId={software.id}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/software/:softwareId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={software.id}
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
            path="/defender_hq/assets/software/:softwareId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={software.id}
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
            path="/defender_hq/assets/software/:softwareId/knowledge/vulnerabilities"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={software.id}
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
            path="/defender_hq/assets/software/:softwareId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={software.id}
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
            path="/defender_hq/assets/software/:softwareId/knowledge/observables"
            render={(routeProps) => (
              <StixCoreObjectStixCyberObservables
                stixCoreObjectId={software.id}
                stixCoreObjectLink={link}
                noRightBar={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/defender_hq/assets/software/:softwareId/knowledge/infrastructures"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={software.id}
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
            path="/defender_hq/assets/software/:softwareId/knowledge/sightings"
            render={(routeProps) => (
              <EntityStixSightingRelationships
                entityId={software.id}
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

SoftwareKnowledgeComponent.propTypes = {
  software: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const SoftwareKnowledge = createFragmentContainer(SoftwareKnowledgeComponent, {
  software: graphql`
    fragment SoftwareKnowledge_software on Campaign {
      id
      name
      aliases
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(SoftwareKnowledge);
