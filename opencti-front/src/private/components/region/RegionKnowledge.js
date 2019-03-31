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

const inversedRelations = [
  'organization',
  'intrusion-set',
  'campaign',
  'incident',
  'malware',
  'threat-actor',
];

class RegionKnowledgeComponent extends Component {
  render() {
    const { classes, region, location } = this.props;
    const link = `/dashboard/catalogs/regions/${region.id}/knowledge`;
    return (
      <div className={classes.container}>
        <RegionHeader region={region} variant="noalias" />
        <RegionKnowledgeBar regionId={region.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/catalogs/regions/:regionId/knowledge/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={region.id}
                {...routeProps}
                inversedRelations={inversedRelations}
              />
            )}
          />

          {location.pathname.includes('overview') ? (
            <StixDomainEntityKnowledge stixDomainEntityId={region.id} />
          ) : (
            ''
          )}

          {location.pathname.includes('countries') ? (
            <EntityStixRelations
              entityId={region.id}
              relationType="localization"
              targetEntityTypes={['Country']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('threats') ? (
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
            />
          ) : (
            ''
          )}

          {location.pathname.includes('attribution') ? (
            <EntityStixRelations
              resolveRelationType="attributed-to"
              entityId={region.id}
              relationType="attributed-to"
              targetEntityTypes={['Identity']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('entities') ? (
            <EntityStixRelations
              entityId={region.id}
              relationType="related-to"
              targetEntityTypes={['Identity']}
              entityLink={link}
            />
          ) : (
            ''
          )}
        </div>
      </div>
    );
  }
}

RegionKnowledgeComponent.propTypes = {
  region: PropTypes.object,
  classes: PropTypes.object,
  location: PropTypes.object,
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
