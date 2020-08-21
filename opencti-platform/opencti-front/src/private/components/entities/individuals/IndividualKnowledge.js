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
import IndividualPopover from './IndividualPopover';
import IndividualKnowledgeBar from './IndividualKnowledgeBar';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class IndividualKnowledgeComponent extends Component {
  render() {
    const { classes, individual } = this.props;
    const link = `/dashboard/entities/individuals/${individual.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={individual}
          PopoverComponent={<IndividualPopover />}
        />
        <IndividualKnowledgeBar individualId={individual.id} />
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
          path="/dashboard/entities/individuals/:individualId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectKnowledge
              stixDomainObjectId={individual.id}
              stixDomainObjectType="Individual"
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
              relationshipType="part-of"
              targetStixDomainObjectTypes={['Organization']}
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
              relationshipType="localization"
              targetStixDomainObjectTypes={['City', 'Country', 'Region']}
              entityLink={link}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/individuals/:individualId/knowledge/threats"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={individual.id}
              relationshipType="targets"
              targetStixDomainObjectTypes={[
                'Country',
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'X-OpenCTI-Incident',
                'Malware',
              ]}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/individuals/:organizationId/knowledge/attribution"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={individual.id}
              relationshipType="attributed-to"
              targetStixDomainObjectTypes={[
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'X-OpenCTI-Incident',
                'Malware',
              ]}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
      </div>
    );
  }
}

IndividualKnowledgeComponent.propTypes = {
  individual: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
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
