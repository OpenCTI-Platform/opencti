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
import IndividualPopover from './IndividualPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectAuthorKnowledge from '../../common/stix_domain_objects/StixDomainObjectAuthorKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: 0,
  },
});

class IndividualKnowledgeComponent extends Component {
  render() {
    const { classes, individual, viewAs, onViewAs } = this.props;
    const link = `/dashboard/entities/individuals/${individual.id}/knowledge`;
    return (
      <div
        className={classes.container}
        style={{ paddingRight: viewAs === 'knowledge' ? 200 : 0 }}
      >
        <StixDomainObjectHeader
          entityType={'Individual'}
          disableSharing={true}
          stixDomainObject={individual}
          PopoverComponent={<IndividualPopover />}
          onViewAs={onViewAs.bind(this)}
          viewAs={viewAs}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={individual.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={individual.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/overview"
            render={(routeProps) => (viewAs === 'knowledge' ? (
                <StixDomainObjectKnowledge
                  stixDomainObjectId={individual.id}
                  stixDomainObjectType="Individual"
                  {...routeProps}
                />
            ) : (
                <StixDomainObjectAuthorKnowledge
                  stixDomainObjectId={individual.id}
                  stixDomainObjectType="Individual"
                  {...routeProps}
                />
            ))
            }
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/threats"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                isRelationReversed
                entityLink={link}
                stixCoreObjectTypes={[
                  'Attack-Pattern',
                  'Theat-Actor-Group',
                  'Intrusion-Set',
                  'Campaign',
                  'Incident',
                  'Malware',
                  'Tool',
                ]}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['related-to']}
                entityLink={link}
                allDirections={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/organizations"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['part-of']}
                stixCoreObjectTypes={['Organization']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/locations"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['located-at']}
                stixCoreObjectTypes={['City', 'Country', 'Region']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Theat-Actor-Group']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Intrusion-Set']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Campaign']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Incident']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Malware']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Attack-Pattern']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Tool']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/observables"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={['Stix-Cyber-Observable']}
                entityLink={link}
                allDirections={true}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
        </Switch>
      </div>
    );
  }
}

IndividualKnowledgeComponent.propTypes = {
  individual: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
};

const IndividualKnowledge = createFragmentContainer(
  IndividualKnowledgeComponent,
  {
    individual: graphql`
      fragment IndividualKnowledge_individual on Individual {
        id
        name
        x_opencti_aliases
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(IndividualKnowledge);
