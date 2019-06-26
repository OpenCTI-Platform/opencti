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
import SectorHeader from './SectorHeader';
import SectorKnowledgeBar from './SectorKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRoles = ['target'];

class SectorKnowledgeComponent extends Component {
  render() {
    const { classes, sector } = this.props;
    const link = `/dashboard/entities/sectors/${sector.id}/knowledge`;
    return (
      <div className={classes.container}>
        <SectorHeader sector={sector} variant="noalias" />
        <SectorKnowledgeBar sectorId={sector.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={sector.id}
                inversedRoles={inversedRoles}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/overview"
            render={routeProps => (
              <StixDomainEntityKnowledge
                stixDomainEntityId={sector.id}
                stixDomainEntityType='sector'
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/organizations"
            render={routeProps => (
              <EntityStixRelations
                entityId={sector.id}
                relationType="gathering"
                targetEntityTypes={['Organization']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/intrusion_sets"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="gathering"
                resolveRelationRole="gather"
                resolveViaTypes={[
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
                entityId={sector.id}
                relationType="targets"
                targetEntityTypes={['Intrusion-Set']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/campaigns"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="gathering"
                resolveRelationRole="gather"
                resolveViaTypes={[
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
                entityId={sector.id}
                relationType="targets"
                targetEntityTypes={['Campaign']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/incidents"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="gathering"
                resolveRelationRole="gather"
                resolveViaTypes={[
                  {
                    entityType: 'Malware',
                    relationType: 'attributed-to',
                    relationRole: 'attribution',
                  },
                ]}
                entityId={sector.id}
                relationType="targets"
                targetEntityTypes={['Incident']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/sectors/:sectorId/knowledge/malwares"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="gathering"
                resolveRelationRole="gather"
                entityId={sector.id}
                relationType="targets"
                targetEntityTypes={['Malware']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
        </div>
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
      ...SectorHeader_sector
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(SectorKnowledge);
