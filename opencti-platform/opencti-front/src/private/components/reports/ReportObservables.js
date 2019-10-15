import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer } from '../../../relay/environment';
import ReportHeader from './ReportHeader';
import ReportObservablesLines from './ReportObservablesLines';

const reportObservablesQuery = graphql`
  query ReportObservablesQuery($id: String!, $relationType: String) {
    report(id: $id) {
      ...ReportHeader_report
      ...ReportObservablesLines_report @arguments(relationType: $relationType)
    }
  }
`;

class ReportObservables extends Component {
  render() {
    const { reportId } = this.props;
    return (
      <div>
        <QueryRenderer
          query={reportObservablesQuery}
          variables={{ id: reportId, relationType: 'indicates' }}
          render={({ props }) => {
            if (props && props.report) {
              return (
                <div>
                  <ReportHeader report={props.report} />
                  <ReportObservablesLines report={props.report} />
                </div>
              );
            }
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

ReportObservables.propTypes = {
  reportId: PropTypes.string,
};

export default ReportObservables;
