import React, { Component } from "react";
import * as PropTypes from "prop-types";
import { Route, withRouter } from "react-router-dom";
import graphql from "babel-plugin-relay/macro";
import {
  QueryRenderer,
  requestSubscription,
} from "../../../../relay/environment";
import TopBar from "../../nav/TopBar";
import Report from "./Report";
import ReportKnowledge from "./ReportKnowledge";
import ReportObservables from "../../common/containers/ContainerStixCyberObservables";
import FileManager from "../../common/files/FileManager";
import StixCoreObjectHistory from "../../common/stix_core_objects/StixCoreObjectHistory";
import ReportHeader from "../../common/containers/ContainerHeader";
import Loader from "../../../../components/Loader";
import ContainerStixCoreObjects from "../../common/containers/ContainerStixCoreObjects";
import ContainerStixCyberObservables from "../../common/containers/ContainerStixCyberObservables";

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
      ...ReportStixCyberObservables_report
      ...ContainerHeader_container
      ...ContainerStixCoreObjects_container
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
            if (props && props.report) {
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
                        <ReportHeader report={props.report} />
                        <ContainerStixCoreObjects
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
                        <ReportHeader report={props.report} />
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
                    render={(routeProps) => (
                      <ReportKnowledge {...routeProps} report={props.report} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/analysis/reports/:reportId/observables"
                    render={(routeProps) => (
                      <ReportObservables
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
                        <ReportHeader report={props.report} />
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
                        <ReportHeader report={props.report} />
                        <StixCoreObjectHistory
                          {...routeProps}
                          entityStandardId={props.report.standard_id}
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

RootReport.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootReport);
