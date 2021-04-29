import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import PositionPopover from './PositionPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectStixCyberObservables from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class PositionKnowledgeComponent extends Component {
  render() {
    const { classes, position } = this.props;
    const link = `/dashboard/entities/positions/${position.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={position}
          PopoverComponent={<PositionPopover />}
          variant="noaliases"
        />
        <Route
          exact
          path="/dashboard/entities/positions/:positionId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship
              entityId={position.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/positions/:positionId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectKnowledge
              stixDomainObjectId={position.id}
              stixDomainObjectType="Position"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/positions/:positionId/knowledge/related"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={position.id}
              relationshipTypes={['related-to']}
              targetStixDomainObjectTypes={['Stix-Domain-Object']}
              entityLink={link}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/positions/:positionId/knowledge/organizations"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={position.id}
              relationshipTypes={['located-at']}
              targetStixDomainObjectTypes={['Organization']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/positions/:positionId/knowledge/threat_actors"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={position.id}
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
          path="/dashboard/entities/positions/:positionId/knowledge/intrusion_sets"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={position.id}
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
          path="/dashboard/entities/positions/:positionId/knowledge/campaigns"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={position.id}
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
          path="/dashboard/entities/positions/:positionId/knowledge/incidents"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={position.id}
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
          path="/dashboard/entities/positions/:positionId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={position.id}
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
          path="/dashboard/entities/positions/:positionId/knowledge/observables"
          render={(routeProps) => (
            <StixCoreObjectStixCyberObservables
              stixCoreObjectId={position.id}
              stixCoreObjectLink={link}
              noRightBar={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/positions/:positionId/knowledge/sightings"
          render={(routeProps) => (
            <EntityStixSightingRelationships
              entityId={position.id}
              entityLink={link}
              noRightBar={true}
              isTo={true}
              {...routeProps}
            />
          )}
        />
      </div>
    );
  }
}

PositionKnowledgeComponent.propTypes = {
  position: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const PositionKnowledge = createFragmentContainer(PositionKnowledgeComponent, {
  position: graphql`
    fragment PositionKnowledge_position on Position {
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
)(PositionKnowledge);
