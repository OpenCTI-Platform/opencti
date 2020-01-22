import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { QueryRenderer } from '../../../relay/environment';
import ReportHeader from './ReportHeader';
import ListLines from '../../../components/list_lines/ListLines';
import ReportStixObservablesLines, {
  reportObservablesLinesQuery,
} from './ReportObservablesLines';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ReportAddObservableRefs from './ReportAddObservableRefs';

class ReportObservablesComponent extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-report-${props.report.id}-stix-observables`,
    );
    this.state = {
      sortBy: propOr('created_at', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-report-${this.props.report.id}-stix-observables`,
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  render() {
    const { report } = this.props;
    const { sortBy, orderAsc, searchTerm } = this.state;
    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      observable_value: {
        label: 'Value',
        width: '35%',
        isSortable: true,
      },
      createdByRef: {
        label: 'Creator',
        width: '15%',
        isSortable: false,
      },
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      markingDefinitions: {
        label: 'Marking',
        isSortable: false,
      },
    };
    const paginationOptions = {
      types: null,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div style={{ paddingBottom: 50 }}>
        <ReportHeader report={report} />
        <br />
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={this.handleSort.bind(this)}
          handleSearch={this.handleSearch.bind(this)}
          secondaryAction={true}
        >
          <QueryRenderer
            query={reportObservablesLinesQuery}
            variables={{ id: report.id, count: 25, ...paginationOptions }}
            render={({ props }) => (
              <ReportStixObservablesLines
                report={props ? props.report : null}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
              />
            )}
          />
        </ListLines>
        <ReportAddObservableRefs
          reportId={report.id}
          paginationOptions={paginationOptions}
        />
      </div>
    );
  }
}

ReportObservablesComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

const ReportObservables = createFragmentContainer(ReportObservablesComponent, {
  report: graphql`
    fragment ReportObservables_report on Report {
      id
      ...ReportHeader_report
    }
  `,
});

export default compose(inject18n)(ReportObservables);
