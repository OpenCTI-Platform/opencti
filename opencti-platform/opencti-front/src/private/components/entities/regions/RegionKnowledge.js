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
import RegionPopover from './RegionPopover';
import RegionKnowledgeBar from './RegionKnowledgeBar';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class RegionKnowledgeComponent extends Component {
  render() {
    const { classes, region } = this.props;
    const link = `/dashboard/entities/regions/${region.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={region}
          PopoverComponent={<RegionPopover />}
        />
        <RegionKnowledgeBar regionId={region.id} />
        <Route
          exact
          path="/dashboard/entities/regions/:regionId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship
              entityId={region.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/regions/:regionId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectKnowledge
              stixDomainObjectId={region.id}
              stixDomainObjectType="Region"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/regions/:regionId/knowledge/countries"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={region.id}
              relationshipType="localization"
              targetEntityTypes={['Country']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/regions/:regionId/knowledge/threats"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={region.id}
              relationshipType="targets"
              targetEntityTypes={[
                'Country',
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'XOpenctiIncident',
                'Malware',
              ]}
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

RegionKnowledgeComponent.propTypes = {
  region: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const RegionKnowledge = createFragmentContainer(RegionKnowledgeComponent, {
  region: graphql`
    fragment RegionKnowledge_region on Region {
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
)(RegionKnowledge);
