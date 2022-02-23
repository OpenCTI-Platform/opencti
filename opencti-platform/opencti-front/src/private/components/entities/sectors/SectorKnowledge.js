import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import SectorPopover from './SectorPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectStixCyberObservables from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class SectorKnowledgeComponent extends Component {
  render() {
    const { classes, sector } = this.props;
    const link = `/dashboard/entities/sectors/${sector.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={sector}
          PopoverComponent={<SectorPopover />}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={sector.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={sector.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectKnowledge
                stixDomainObjectId={sector.id}
                stixDomainObjectType="Sector"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={sector.id}
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
                allDirections={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/organizations"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={sector.id}
                relationshipTypes={['part-of']}
                targetStixDomainObjectTypes={['Organization']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={sector.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Threat-Actor']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={sector.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Intrusion-Set']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={sector.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Campaign']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={sector.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Incident']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={sector.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Malware']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={sector.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Attack-Pattern']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={sector.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Tool']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/observables"
            render={(routeProps) => (
              <StixCoreObjectStixCyberObservables
                stixCoreObjectId={sector.id}
                stixCoreObjectLink={link}
                noRightBar={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:threatActorId/knowledge/sightings"
            render={(routeProps) => (
              <EntityStixSightingRelationships
                entityId={sector.id}
                entityLink={link}
                noRightBar={true}
                isTo={true}
                {...routeProps}
              />
            )}
          />
        </Switch>
      </div>
    );
  }
}

SectorKnowledgeComponent.propTypes = {
  sector: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const SectorKnowledge = createFragmentContainer(SectorKnowledgeComponent, {
  sector: graphql`
    fragment SectorKnowledge_sector on Sector {
      id
      name
      x_opencti_aliases
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(SectorKnowledge);
