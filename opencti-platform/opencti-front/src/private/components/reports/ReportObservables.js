import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  append, compose, filter, propOr,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { withStyles } from '@material-ui/core';
import { QueryRenderer } from '../../../relay/environment';
import ReportHeader from './ReportHeader';
import ListLines from '../../../components/list_lines/ListLines';
import ReportObservablesLines, {
  reportObservablesLinesQuery,
} from './ReportObservablesLines';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ReportAddObservableRefs from './ReportAddObservableRefs';
import StixObservablesRightBar from '../signatures/stix_observables/StixObservablesRightBar';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 250px 0 0',
  },
});

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
      types: [],
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
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

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports });
  }

  handleToggle(type) {
    if (this.state.types.includes(type)) {
      this.setState({ types: filter((t) => t !== type, this.state.types) }, () => this.saveView());
    } else {
      this.setState({ types: append(type, this.state.types) }, () => this.saveView());
    }
  }

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  render() {
    const { report, classes } = this.props;
    const {
      sortBy,
      orderAsc,
      searchTerm,
      types,
      openExports,
      numberOfElements,
    } = this.state;
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
      types,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        <ReportHeader report={report} />
        <br />
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={this.handleSort.bind(this)}
          handleSearch={this.handleSearch.bind(this)}
          secondaryAction={true}
          numberOfElements={numberOfElements}
        >
          <QueryRenderer
            query={reportObservablesLinesQuery}
            variables={{ id: report.id, count: 25, ...paginationOptions }}
            render={({ props }) => (
              <ReportObservablesLines
                report={props ? props.report : null}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            )}
          />
        </ListLines>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ReportAddObservableRefs
            reportId={report.id}
            paginationOptions={paginationOptions}
          />
        </Security>
        <StixObservablesRightBar
          types={types}
          handleToggle={this.handleToggle.bind(this)}
          openExports={openExports}
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

export default compose(inject18n, withStyles(styles))(ReportObservables);
