import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer } from '../../../relay/environment';
import TopBar from '../nav/TopBar';
import Report from './Report';
import ReportKnowledge from './ReportKnowledge';

const reportQuery = graphql`
    query RootReportQuery($id: String!) {
        report(id: $id) {
            ...Report_report
            ...ReportHeader_report
            ...ReportOverview_report
            ...ReportKnowledge_report
        }
    }
`;

class RootReport extends Component {
  render() {
    const { me, handleSearch, match: { params: { reportId } } } = this.props;
    return (
      <div>
        <TopBar me={me || null} handleSearch={handleSearch.bind(this)}/>
        <QueryRenderer
          query={reportQuery}
          variables={{ id: reportId }}
          render={({ props }) => {
            if (props && props.report) {
              return (
                <div>
                  <Route exact path='/dashboard/reports/all/:reportId' render={
                    routeProps => <Report {...routeProps} report={props.report}/>
                  }/>
                  <Route exact path='/dashboard/reports/all/:reportId/knowledge' render={
                    routeProps => <ReportKnowledge {...routeProps} report={props.report}/>
                  }/>
                </div>
              );
            }
            return (
              <div> &nbsp; </div>
            );
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
  handleSearch: PropTypes.func,
};

export default withRouter(RootReport);
