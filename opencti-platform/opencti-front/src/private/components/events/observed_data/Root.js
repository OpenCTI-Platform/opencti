import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import ObservedData from './ObservedData';
import ObservedDataPopover from './ObservedDataPopover';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';

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
      ...FilePendingViewer_entity
    }
  }
`;

const observedDataQuery = graphql`
  query RootObservedDataQuery($id: String!) {
    observedData(id: $id) {
      standard_id
      ...ObservedData_observedData
      ...ObservedDataDetails_observedData
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixCyberObservables_container
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
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
      me,
      match: {
        params: { observedDataId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={observedDataQuery}
          variables={{ id: observedDataId }}
          render={({ props }) => {
            if (props && props.observedData) {
              return (
                <div>
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
                      <React.Fragment>
                        <ContainerHeader
                          container={props.observedData}
                          PopoverComponent={<ObservedDataPopover />}
                        />
                        <ContainerStixDomainObjects
                          {...routeProps}
                          container={props.observedData}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/events/observed_data/:observedDataId/observables"
                    render={(routeProps) => (
                      <React.Fragment>
                        <ContainerHeader
                          container={props.observedData}
                          PopoverComponent={<ObservedDataPopover />}
                        />
                        <ContainerStixCyberObservables
                          {...routeProps}
                          container={props.observedData}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/events/observed_data/:observedDataId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <ContainerHeader
                          container={props.observedData}
                          PopoverComponent={<ObservedDataPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={observedDataId}
                          connectorsExport={props.connectorsForExport}
                          connectorsImport={props.connectorsForImport}
                          entity={props.observedData}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/events/observed_data/:observedDataId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <ContainerHeader
                          container={props.observedData}
                          PopoverComponent={<ObservedDataPopover />}
                        />
                        <StixCoreObjectHistory
                          {...routeProps}
                          stixCoreObjectId={observedDataId}
                        />
                      </React.Fragment>
                    )}
                  />
                </div>
              );
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootObservedData.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootObservedData);
