import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import SystemPopover from './SystemPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectStixCyberObservables from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectAuthorKnowledge from '../../common/stix_domain_objects/StixDomainObjectAuthorKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: 0,
  },
});

class SystemKnowledgeComponent extends Component {
  render() {
    const { classes, system, viewAs, onViewAs } = this.props;
    const link = `/dashboard/entities/systems/${system.id}/knowledge`;
    return (
      <div
        className={classes.container}
        style={{ paddingRight: viewAs === 'knowledge' ? 200 : 0 }}
      >
        <StixDomainObjectHeader
          stixDomainObject={system}
          PopoverComponent={<SystemPopover />}
          onViewAs={onViewAs.bind(this)}
          viewAs={viewAs}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/entities/systems/:systemId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={system.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/systems/:systemId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={system.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/systems/:systemId/knowledge/overview"
            render={(routeProps) => (viewAs === 'knowledge' ? (
                <StixDomainObjectKnowledge
                  stixDomainObjectId={system.id}
                  stixDomainObjectType="System"
                  {...routeProps}
                />
            ) : (
                <StixDomainObjectAuthorKnowledge
                  stixDomainObjectId={system.id}
                  stixDomainObjectType="System"
                  {...routeProps}
                />
            ))
            }
          />
          <Route
            exact
            path="/dashboard/entities/systems/:systemId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={system.id}
                relationshipTypes={['related-to']}
                targetStixDomainObjectTypes={[
                  'Threat-Actor',
                  'Intrusion-Set',
                  'Campaign',
                  'Incident',
                  'Malware',
                  'Tool',
                  'Vulnerability',
                  'System',
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
            path="/dashboard/entities/systems/:systemId/knowledge/systems"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={system.id}
                relationshipTypes={['part-of']}
                targetStixDomainObjectTypes={['System']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/systems/:systemId/knowledge/locations"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={system.id}
                relationshipTypes={['localization']}
                targetStixDomainObjectTypes={['City', 'Country', 'Region']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/systems/:systemId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={system.id}
                targetStixDomainObjectTypes={['Threat-Actor']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/systems/:systemId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={system.id}
                targetStixDomainObjectTypes={['Intrusion-Set']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/systems/:systemId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={system.id}
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
            path="/dashboard/entities/systems/:systemId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={system.id}
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
            path="/dashboard/entities/systems/:systemId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={system.id}
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
            path="/dashboard/entities/systems/:systemId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={system.id}
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
            path="/dashboard/entities/systems/:systemId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={system.id}
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
            path="/dashboard/entities/systems/:systemId/knowledge/observables"
            render={(routeProps) => (
              <StixCoreObjectStixCyberObservables
                stixCoreObjectId={system.id}
                stixCoreObjectLink={link}
                noRightBar={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/systems/:systemId/knowledge/sightings"
            render={(routeProps) => (
              <EntityStixSightingRelationships
                entityId={system.id}
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

SystemKnowledgeComponent.propTypes = {
  system: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
};

const SystemKnowledge = createFragmentContainer(SystemKnowledgeComponent, {
  system: graphql`
    fragment SystemKnowledge_system on System {
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
)(SystemKnowledge);
