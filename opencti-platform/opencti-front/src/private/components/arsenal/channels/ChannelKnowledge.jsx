import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ChannelPopover from './ChannelPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class ChannelKnowledgeComponent extends Component {
  render() {
    const { classes, channel } = this.props;
    const link = `/dashboard/arsenal/channels/${channel.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          entityType={'Channel'}
          stixDomainObject={channel}
          PopoverComponent={<ChannelPopover />}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={channel.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={channel.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={channel.id}
                stixDomainObjectType="Channel"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['related-to']}
                entityLink={link}
                allDirections={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/victimology"
            render={(routeProps) => (
              <StixDomainObjectVictimology
                stixDomainObjectId={channel.id}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Threat-Actor-Group']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Intrusion-Set']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Campaign']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Attack-Pattern']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/channels"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['amplifies']}
                stixCoreObjectTypes={['Channel']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['uses', 'delivers', 'drops']}
                stixCoreObjectTypes={['Malware']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/vulnerabilities"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Vulnerability']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Incident']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/observables"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={channel.id}
                relationshipTypes={[
                  'related-to',
                  'publishes',
                  'uses',
                  'belongs-to',
                ]}
                stixCoreObjectTypes={['Stix-Cyber-Observable']}
                entityLink={link}
                allDirections={true}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/channels/:channelId/knowledge/sightings"
            render={(routeProps) => (
              <EntityStixSightingRelationships
                entityId={channel.id}
                entityLink={link}
                noRightBar={true}
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

ChannelKnowledgeComponent.propTypes = {
  channel: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ChannelKnowledge = createFragmentContainer(ChannelKnowledgeComponent, {
  channel: graphql`
    fragment ChannelKnowledge_channel on Channel {
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
)(ChannelKnowledge);
