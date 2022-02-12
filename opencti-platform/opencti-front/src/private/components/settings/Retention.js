import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withRouter } from 'react-router-dom';
import withTheme from '@mui/styles/withTheme';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import RetentionLines, {
  RetentionLinesQuery,
} from './retention/RetentionLines';
import RetentionCreation from './retention/RetentionCreation';

class Retention extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'retention-view',
    );
    this.state = {
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'retention-view',
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  renderLines(paginationOptions) {
    const { searchTerm } = this.state;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '15%',
      },
      filters: {
        label: 'Apply on',
        width: '35%',
      },
      retention: {
        label: 'Max retention',
        width: '20%',
      },
      last_execution_date: {
        label: 'Last execution',
        width: '20%',
      },
      remaining_count: {
        label: 'Remaining',
        width: '10%',
      },
    };
    return (
      <ListLines
        dataColumns={dataColumns}
        handleSearch={this.handleSearch.bind(this)}
        displayImport={false}
        secondaryAction={true}
        keyword={searchTerm}
      >
        <QueryRenderer
          query={RetentionLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <RetentionLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const { view, searchTerm } = this.state;
    const paginationOptions = { search: searchTerm };
    return (
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <RetentionCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

Retention.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(inject18n, withTheme, withRouter)(Retention);
