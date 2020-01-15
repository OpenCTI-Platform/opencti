import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixRelations from '../../common/stix_relations/EntityStixRelations';
import StixDomainEntityKnowledge from '../../common/stix_domain_entities/StixDomainEntityKnowledge';
import StixRelation from '../../common/stix_relations/StixRelation';
import RegionPopover from './RegionPopover';
import RegionKnowledgeBar from './RegionKnowledgeBar';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

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
        <StixDomainEntityHeader
          stixDomainEntity={region}
          PopoverComponent={<RegionPopover />}
        />
        <RegionKnowledgeBar regionId={region.id} />
        <Route
          exact
          path="/dashboard/entities/regions/:regionId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
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
            <StixDomainEntityKnowledge
              stixDomainEntityId={region.id}
              stixDomainEntityType="region"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/regions/:regionId/knowledge/countries"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={region.id}
              relationType="localization"
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
            <EntityStixRelations
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
      alias
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(RegionKnowledge);
