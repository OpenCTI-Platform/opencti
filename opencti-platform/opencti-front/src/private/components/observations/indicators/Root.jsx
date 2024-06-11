import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
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
import Breadcrumbs from '../../../../components/Breadcrumbs';
import withRouter from '../../../../utils/compat-router/withRouter';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

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
      pattern
      ...Indicator_indicator
      ...IndicatorDetails_indicator
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectContent_stixCoreObject
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
      params: { indicatorId },
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
      params: { indicatorId },
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
                const paddingRight = getPaddingRight(location.pathname, indicator.id, '/dashboard/observations/indicators', false);
                return (
                  <div style={{ paddingRight }}>
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Observations') },
                      { label: t('Indicators'), link: '/dashboard/observations/indicators' },
                      { label: indicator.name || indicator.pattern, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Indicator"
                      stixDomainObject={indicator}
                      PopoverComponent={<IndicatorPopover/>}
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
                        value={getCurrentTab(location.pathname, indicator.id, '/dashboard/observations/indicators')}
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
                          to={`/dashboard/observations/indicators/${indicator.id}/content`}
                          value={`/dashboard/observations/indicators/${indicator.id}/content`}
                          label={t('Content')}
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
                    <Routes>
                      <Route
                        path="/"
                        element={(<Indicator indicator={indicator}/>)}
                      />
                      <Route
                        path="/content/*"
                        element={
                          <StixCoreObjectContentRoot
                            stixCoreObject={indicator}
                          />
                                }
                      />
                      <Route
                        path="/analyses"
                        element={(
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            stixDomainObjectOrStixCoreRelationship={indicator}
                          />
                                )}
                      />
                      <Route
                        path="/sightings"
                        element={(
                          <EntityStixSightingRelationships
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
                        path="/files"
                        element={(
                          <FileManager
                            id={indicatorId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.indicator}
                          />
                                )}
                      />
                      <Route
                        path="/history"
                        element={(
                          <StixCoreObjectHistory
                            stixCoreObjectId={indicatorId}
                          />
                                )}
                      />
                      <Route
                        path="/knowledge"
                        element={(
                          <IndicatorEntities
                            indicatorId={indicatorId}
                          />
                                )}
                      />
                      <Route
                        path="/knowledge/relations/:relationId"
                        element={(
                          <StixCoreRelationship
                            entityId={indicatorId}
                          />
                                )}
                      />
                      <Route
                        path="/knowledge/sightings/:sightingId"
                        element={(
                          <StixSightingRelationship
                            entityId={indicatorId}
                          />
                                )}
                      />
                    </Routes>
                  </div>
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
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootIndicator);
