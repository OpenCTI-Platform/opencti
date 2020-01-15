import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer } from '../../../relay/environment';
import ReportHeader from './ReportHeader';
import ReportObservablesLines from './ReportObservablesLines';
import Loader from '../../../components/Loader';

const reportObservablesQuery = graphql`
  query ReportObservablesQuery($id: String!) {
    report(id: $id) {
      ...ReportHeader_report
      ...ReportObservablesLines_report
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
          variables={{ id: reportId }}
          render={({ props }) => {
            if (props && props.report) {
              return (
                <div>
                  <ReportHeader report={props.report} />
                  <ReportObservablesLines report={props.report} />
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

ReportObservables.propTypes = {
  reportId: PropTypes.string,
};

export default ReportObservables;
