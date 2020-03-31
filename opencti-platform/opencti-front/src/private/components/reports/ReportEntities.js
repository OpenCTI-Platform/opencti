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
import ReportEntitiesLines, {
  ReportEntitiesLinesQuery,
} from './ReportEntitiesLines';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import StixDomainEntitiesRightBar from '../common/stix_domain_entities/StixDomainEntitiesRightBar';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 90px 0',
  },
});

class ReportEntitiesComponent extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-report-${props.report.id}-stix-domain-entities`,
    );
    this.state = {
      sortBy: propOr('name', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      stixDomainEntitiesTypes: propOr([], 'stixDomainEntitiesTypes', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-report-${this.props.report.id}-stix-domain-entities`,
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

  handleToggleStixDomainEntityType(type) {
    if (this.state.stixDomainEntitiesTypes.includes(type)) {
      this.setState(
        {
          stixDomainEntitiesTypes: filter(
            (t) => t !== type,
            this.state.stixDomainEntitiesTypes,
          ),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          stixDomainEntitiesTypes: append(
            type,
            this.state.stixDomainEntitiesTypes,
          ),
        },
        () => this.saveView(),
      );
    }
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
      stixDomainEntitiesTypes,
      openExports,
      numberOfElements,
    } = this.state;
    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '30%',
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
    const filters = [
      { key: 'entity_type', values: stixDomainEntitiesTypes, operator: 'match' },
    ];
    const paginationOptions = {
      filters,
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
          keyword={searchTerm}
          secondaryAction={true}
          numberOfElements={numberOfElements}
        >
          <QueryRenderer
            query={ReportEntitiesLinesQuery}
            variables={{ id: report.id, count: 25, ...paginationOptions }}
            render={({ props }) => (
              <ReportEntitiesLines
                report={props ? props.report : null}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            )}
          />
        </ListLines>
        <StixDomainEntitiesRightBar
          stixDomainEntitiesTypes={stixDomainEntitiesTypes}
          handleToggleStixDomainEntityType={this.handleToggleStixDomainEntityType.bind(
            this,
          )}
          openExports={openExports}
        />
      </div>
    );
  }
}

ReportEntitiesComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

const ReportEntities = createFragmentContainer(ReportEntitiesComponent, {
  report: graphql`
    fragment ReportEntities_report on Report {
      id
      ...ReportHeader_report
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ReportEntities);
