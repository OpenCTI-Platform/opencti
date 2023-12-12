import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import Indicator from './Indicator';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import IndicatorEntities from './IndicatorEntities';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import FileManager from '../../common/files/FileManager';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import IndicatorPopover from './IndicatorPopover';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import inject18n from '../../../../components/i18n';

const subscription = graphql`
  subscription RootIndicatorSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Indicator {
        ...Indicator_indicator
        ...IndicatorEditionContainer_indicator
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const indicatorQuery = graphql`
  query RootIndicatorQuery($id: String!) {
    indicator(id: $id) {
      id
      standard_id
      entity_type
      name
      ...Indicator_indicator
      ...IndicatorDetails_indicator
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootIndicator extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { indicatorId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: indicatorId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      t,
      location,
      match: {
        params: { indicatorId },
      },
    } = this.props;
    return (
      <>
        <QueryRenderer
          query={indicatorQuery}
          variables={{ id: indicatorId, relationship_type: 'indicates' }}
          render={({ props }) => {
            if (props) {
              if (props.indicator) {
                const { indicator } = props;
                return (
                  <>
                    <StixDomainObjectHeader
                      entityType="Indicator"
                      stixDomainObject={indicator}
                      PopoverComponent={<IndicatorPopover />}
                      noAliases={true}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={
                          location.pathname.includes(
                            `/dashboard/observations/indicators/${indicator.id}/knowledge`,
                          )
                            ? `/dashboard/observations/indicators/${indicator.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/indicators/${indicator.id}`}
                          value={`/dashboard/observations/indicators/${indicator.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/indicators/${indicator.id}/knowledge`}
                          value={`/dashboard/observations/indicators/${indicator.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/indicators/${indicator.id}/analyses`}
                          value={`/dashboard/observations/indicators/${indicator.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/indicators/${indicator.id}/sightings`}
                          value={`/dashboard/observations/indicators/${indicator.id}/sightings`}
                          label={t('Sightings')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/indicators/${indicator.id}/files`}
                          value={`/dashboard/observations/indicators/${indicator.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/indicators/${indicator.id}/history`}
                          value={`/dashboard/observations/indicators/${indicator.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/observations/indicators/:indicatorId"
                        render={(routeProps) => (
                          <Indicator {...routeProps} indicator={indicator} />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/indicators/:indicatorId/analyses"
                        render={(routeProps) => (
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={indicator}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/indicators/:indicatorId/sightings"
                        render={(routeProps) => (
                          <EntityStixSightingRelationships
                            {...routeProps}
                            entityId={indicatorId}
                            noPadding={true}
                            stixCoreObjectTypes={[
                              'Region',
                              'Country',
                              'City',
                              'Sector',
                              'Organization',
                              'Individual',
                              'System',
                            ]}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/indicators/:indicatorId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={indicatorId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.indicator}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/indicators/:indicatorId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={indicatorId}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/indicators/:indicatorId/knowledge"
                        render={(routeProps) => (
                          <IndicatorEntities
                            {...routeProps}
                            indicatorId={indicatorId}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/indicators/:indicatorId/knowledge/relations/:relationId"
                        render={(routeProps) => (
                          <StixCoreRelationship
                            entityId={indicatorId}
                            {...routeProps}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/indicators/:indicatorId/knowledge/sightings/:sightingId"
                        render={(routeProps) => (
                          <StixSightingRelationship
                            entityId={indicatorId}
                            {...routeProps}
                          />
                        )}
                      />
                    </Switch>
                  </>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </>
    );
  }
}

RootIndicator.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootIndicator);
