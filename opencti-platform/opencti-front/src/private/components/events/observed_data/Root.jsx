import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import ObservedData from './ObservedData';
import ObservedDataPopover from './ObservedDataPopover';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import inject18n from '../../../../components/i18n';
import BreadcrumbHeader from '../../../../components/BreadcrumbHeader';

const subscription = graphql`
  subscription RootObservedDataSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on ObservedData {
        ...ObservedData_observedData
        ...ObservedDataEditionContainer_observedData
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const observedDataQuery = graphql`
  query RootObservedDataQuery($id: String!) {
    observedData(id: $id) {
      id
      standard_id
      entity_type
      ...ObservedData_observedData
      ...ObservedDataDetails_observedData
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixCyberObservables_container
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
  }
`;

class RootObservedData extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { observedDataId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: observedDataId },
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
        params: { observedDataId },
      },
    } = this.props;
    const path = [
      { text: t('Events') },
      {
        text: t('Observed data'),
        link: '/dashboard/events/observed_data',
      },
    ];
    return (
      <>
        <QueryRenderer
          query={observedDataQuery}
          variables={{ id: observedDataId }}
          render={({ props }) => {
            if (props && props.observedData) {
              const { observedData } = props;
              return (
                <div
                  style={{
                    paddingRight:
                      location.pathname.includes(
                        `/dashboard/events/observed_data/${observedData.id}/entities`,
                      )
                      || location.pathname.includes(
                        `/dashboard/events/observed_data/${observedData.id}/observables`,
                      )
                        ? 260
                        : 0,
                  }}
                >
                  <BreadcrumbHeader path={path}>
                    <ContainerHeader
                      container={observedData}
                      PopoverComponent={<ObservedDataPopover />}
                    />
                  </BreadcrumbHeader>
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
                          `/dashboard/events/observed_data/${observedData.id}/knowledge`,
                        )
                          ? `/dashboard/events/observed_data/${observedData.id}/knowledge`
                          : location.pathname
                      }
                    >
                      <Tab
                        component={Link}
                        to={`/dashboard/events/observed_data/${observedData.id}`}
                        value={`/dashboard/events/observed_data/${observedData.id}`}
                        label={t('Overview')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/events/observed_data/${observedData.id}/entities`}
                        value={`/dashboard/events/observed_data/${observedData.id}/entities`}
                        label={t('Entities')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/events/observed_data/${observedData.id}/observables`}
                        value={`/dashboard/events/observed_data/${observedData.id}/observables`}
                        label={t('Observables')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/events/observed_data/${observedData.id}/files`}
                        value={`/dashboard/events/observed_data/${observedData.id}/files`}
                        label={t('Data')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/events/observed_data/${observedData.id}/history`}
                        value={`/dashboard/events/observed_data/${observedData.id}/history`}
                        label={t('History')}
                      />
                    </Tabs>
                  </Box>
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/events/observed_data/:observedDataId"
                      render={(routeProps) => (
                        <ObservedData
                          {...routeProps}
                          observedData={props.observedData}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/observed_data/:observedDataId/entities"
                      render={(routeProps) => (
                        <ContainerStixDomainObjects
                          {...routeProps}
                          container={props.observedData}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/observed_data/:observedDataId/observables"
                      render={(routeProps) => (
                        <ContainerStixCyberObservables
                          {...routeProps}
                          container={props.observedData}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/observed_data/:observedDataId/files"
                      render={(routeProps) => (
                        <FileManager
                          {...routeProps}
                          id={observedDataId}
                          connectorsExport={props.connectorsForExport}
                          connectorsImport={props.connectorsForImport}
                          entity={props.observedData}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/observed_data/:observedDataId/history"
                      render={(routeProps) => (
                        <StixCoreObjectHistory
                          {...routeProps}
                          stixCoreObjectId={observedDataId}
                        />
                      )}
                    />
                  </Switch>
                </div>
              );
            }
            return <Loader />;
          }}
        />
      </>
    );
  }
}

RootObservedData.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootObservedData);
