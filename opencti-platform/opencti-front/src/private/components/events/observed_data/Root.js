import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import ObservedData from './ObservedData';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ObservedDataPopover from './ObservedDataPopover';

const subscription = graphql`
  subscription RootObservedDataSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on ObservedData {
        ...ObservedData_observedData
        ...ObservedDataEditionContainer_observedData
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
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
      ...ContainerStixObjectsOrStixRelationships_container
      ...FileImportViewer_entity
      ...FileExportViewer_entity
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
  componentDidMount() {
    const {
      match: {
        params: { observedDataId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: observedDataId },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
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
                    path="/dashboard/analysis/observed_data/:observedDataId"
                    render={(routeProps) => (
                      <ObservedData
                        {...routeProps}
                        observedData={props.observedData}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/analysis/observed_data/:observedDataId/files"
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
                    path="/dashboard/analysis/observed_data/:observedDataId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <ContainerHeader
                          container={props.observedData}
                          PopoverComponent={<ObservedDataPopover />}
                        />
                        <StixCoreObjectHistory
                          {...routeProps}
                          entityStandardId={props.observedData.standard_id}
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
