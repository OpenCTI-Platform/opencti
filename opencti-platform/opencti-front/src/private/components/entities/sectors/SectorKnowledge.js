import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import SectorPopover from './SectorPopover';
import SectorKnowledgeBar from './SectorKnowledgeBar';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';

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
        <StixDomainObjectHeader
          stixDomainObject={sector}
          PopoverComponent={<SectorPopover />}
        />
        <SectorKnowledgeBar sectorId={sector.id} />
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
          path="/dashboard/entities/sectors/:sectorId/knowledge/organizations"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={sector.id}
              relationshipType="part-of"
              targetStixDomainObjectTypes={['Organization']}
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
              relationshipType="targets"
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
              relationshipType="targets"
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
              relationshipType="targets"
              targetStixDomainObjectTypes={['X-OpenCTI-Incident']}
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
              relationshipType="targets"
              targetStixDomainObjectTypes={['Malware']}
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
      aliases
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(SectorKnowledge);
