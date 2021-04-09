import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Redirect, Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Report from './Report';
import ReportPopover from './ReportPopover';
import ReportKnowledge from './ReportKnowledge';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootReportSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Report {
        ...Report_report
        ...ReportKnowledgeGraph_report
        ...ReportEditionContainer_report
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const reportQuery = graphql`
  query RootReportQuery($id: String!) {
    report(id: $id) {
      standard_id
      ...Report_report
      ...ReportDetails_report
      ...ReportKnowledge_report
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixCyberObservables_container
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

class RootReport extends Component {
  componentDidMount() {
    const {
      match: {
        params: { reportId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: reportId },
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
        params: { reportId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={reportQuery}
          variables={{ id: reportId }}
          render={({ props }) => {
            if (props) {
              if (props.report) {
                return (
                  <div>
                    <Route
                      exact
                      path="/dashboard/analysis/reports/:reportId"
                      render={(routeProps) => (
                        <Report {...routeProps} report={props.report} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analysis/reports/:reportId/entities"
                      render={(routeProps) => (
                        <React.Fragment>
                          <ContainerHeader
                            container={props.report}
                            PopoverComponent={<ReportPopover />}
                          />
                          <ContainerStixDomainObjects
                            {...routeProps}
                            container={props.report}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analysis/reports/:reportId/observables"
                      render={(routeProps) => (
                        <React.Fragment>
                          <ContainerHeader
                            container={props.report}
                            PopoverComponent={<ReportPopover />}
                          />
                          <ContainerStixCyberObservables
                            {...routeProps}
                            container={props.report}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analysis/reports/:reportId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/analysis/reports/${reportId}/knowledge/graph`}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analysis/reports/:reportId/knowledge/:mode"
                      render={(routeProps) => (
                        <ReportKnowledge
                          {...routeProps}
                          report={props.report}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analysis/reports/:reportId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <ContainerHeader
                            container={props.report}
                            PopoverComponent={<ReportPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={reportId}
                            connectorsExport={props.connectorsForExport}
                            connectorsImport={props.connectorsForImport}
                            entity={props.report}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analysis/reports/:reportId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <ContainerHeader
                            container={props.report}
                            PopoverComponent={<ReportPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={reportId}
                            withoutRelations={true}
                          />
                        </React.Fragment>
                      )}
                    />
                  </div>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootReport.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootReport);
