import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityStixRelations from '../stix_relation/EntityStixRelations';
import StixDomainEntityKnowledge from '../stix_domain_entity/StixDomainEntityKnowledge';
import StixRelation from '../stix_relation/StixRelation';
import RegionHeader from './RegionHeader';
import RegionKnowledgeBar from './RegionKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRoles = ['location', 'target'];

class RegionKnowledgeComponent extends Component {
  render() {
    const { classes, region } = this.props;
    const link = `/dashboard/entities/regions/${region.id}/knowledge`;
    return (
      <div className={classes.container}>
        <RegionHeader region={region} variant="noalias" />
        <RegionKnowledgeBar regionId={region.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/entities/regions/:regionId/knowledge/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={region.id}
                inversedRoles={inversedRoles}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/regions/:regionId/knowledge/overview"
            render={routeProps => (
              <StixDomainEntityKnowledge
                stixDomainEntityId={region.id}
                stixDomainEntityType='region'
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/regions/:regionId/knowledge/countries"
            render={routeProps => (
              <EntityStixRelations
                entityId={region.id}
                relationType="localization"
                targetEntityTypes={['Country']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/regions/:regionId/knowledge/threats"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="localization"
                resolveRelationRole="location"
                entityId={region.id}
                relationType="targets"
                targetEntityTypes={[
                  'Country',
                  'Threat-Actor',
                  'Intrusion-Set',
                  'Campaign',
                  'Incident',
                  'Malware',
                ]}
                entityLink={link}
                resolveViaTypes={[
                  {
                    entityType: 'Intrusion-Set',
                    relationType: 'attributed-to',
                    relationRole: 'attribution',
                  },
                  {
                    entityType: 'Campaign',
                    relationType: 'attributed-to',
                    relationRole: 'attribution',
                  },
                  {
                    entityType: 'Incident',
                    relationType: 'attributed-to',
                    relationRole: 'attribution',
                  },
                  {
                    entityType: 'Malware',
                    relationType: 'attributed-to',
                    relationRole: 'attribution',
                  },
                ]}
                {...routeProps}
              />
            )}
          />
        </div>
      </div>
    );
  }
}

RegionKnowledgeComponent.propTypes = {
  region: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const RegionKnowledge = createFragmentContainer(RegionKnowledgeComponent, {
  region: graphql`
    fragment RegionKnowledge_region on Region {
      id
      ...RegionHeader_region
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(RegionKnowledge);
