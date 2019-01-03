import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { QueryRenderer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import environment from '../../../relay/environment';
import TopBar from '../nav/TopBar';
import Report from './Report';

const reportQuery = graphql`
    query RootReportQuery($id: String!) {
        report(id: $id) {
            ...Report_report
            ...ReportHeader_report
            ...ReportOverview_report
        }
    }
`;

class RootReport extends Component {
  render() {
    const { me, match: { params: { reportId } } } = this.props;
    return (
      <div>
        <TopBar me={me || null}/>
        <QueryRenderer
          environment={environment}
          query={reportQuery}
          variables={{ id: reportId }}
          render={({ props }) => (
            <Route exact path='/dashboard/reports/all/:reportId' render={routeProps => <Report
              {...routeProps}
              reportId={reportId}
              report={props && props.report ? props.report : null}/>
            }/>
          )}
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
