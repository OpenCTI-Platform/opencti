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
import EventPopover from './EventPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class EventKnowledgeComponent extends Component {
  render() {
    const { classes, event } = this.props;
    const link = `/dashboard/entities/events/${event.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          entityType={'Event'}
          stixDomainObject={event}
          PopoverComponent={<EventPopover />}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/entities/events/:eventId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={event.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/events/:eventId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={event.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/events/:eventId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectKnowledge
                stixDomainObjectId={event.id}
                stixDomainObjectType="Event"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/events/:eventId/knowledge/threats"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={event.id}
                relationshipTypes={['targets']}
                isRelationReversed
                entityLink={link}
                stixCoreObjectTypes={[
                  'Attack-Pattern',
                  'Threat-Actor',
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
            path="/dashboard/entities/events/:eventId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={event.id}
                relationshipTypes={['related-to']}
                entityLink={link}
                allDirections={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/events/:eventId/knowledge/locations"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={event.id}
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
            path="/dashboard/entities/events/:eventId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={event.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Threat-Actor']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/events/:eventId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={event.id}
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
            path="/dashboard/entities/events/:eventId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={event.id}
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
            path="/dashboard/entities/events/:eventId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={event.id}
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
            path="/dashboard/entities/events/:eventId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={event.id}
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
            path="/dashboard/entities/events/:eventId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={event.id}
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
            path="/dashboard/entities/events/:eventId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={event.id}
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
            path="/dashboard/entities/events/:eventId/knowledge/observables"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={event.id}
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

EventKnowledgeComponent.propTypes = {
  event: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const EventKnowledge = createFragmentContainer(EventKnowledgeComponent, {
  event: graphql`
    fragment EventKnowledge_event on Event {
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
)(EventKnowledge);
