import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixRelations from '../../common/stix_relations/EntityStixRelations';
import StixDomainEntityKnowledge from '../../common/stix_domain_entities/StixDomainEntityKnowledge';
import StixRelation from '../../common/stix_relations/StixRelation';
import SectorPopover from './SectorPopover';
import SectorKnowledgeBar from './SectorKnowledgeBar';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class SectorKnowledgeComponent extends Component {
  render() {
    const { classes, sector } = this.props;
    const link = `/dashboard/entities/sectors/${sector.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={sector}
          PopoverComponent={<SectorPopover />}
        />
        <SectorKnowledgeBar sectorId={sector.id} />
        <Route
          exact
          path="/dashboard/entities/sectors/:sectorId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
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
            <StixDomainEntityKnowledge
              stixDomainEntityId={sector.id}
              stixDomainEntityType="sector"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/sectors/:sectorId/knowledge/organizations"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={sector.id}
              relationType="gathering"
              targetEntityTypes={['Organization']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/sectors/:sectorId/knowledge/intrusion_sets"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={sector.id}
              relationType="targets"
              targetEntityTypes={['Intrusion-Set']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/sectors/:sectorId/knowledge/campaigns"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={sector.id}
              relationType="targets"
              targetEntityTypes={['Campaign']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/sectors/:sectorId/knowledge/incidents"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={sector.id}
              relationType="targets"
              targetEntityTypes={['Incident']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/sectors/:sectorId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={sector.id}
              relationType="targets"
              targetEntityTypes={['Malware']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
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
      alias
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(SectorKnowledge);
