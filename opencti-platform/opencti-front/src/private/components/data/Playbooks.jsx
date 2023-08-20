/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withRouter } from 'react-router-dom';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import PlaybooksLines, { PlaybooksLinesQuery } from './playbooks/PlaybooksLines';
import PlaybookCreation from './playbooks/PlaybookCreation';
import ProcessingMenu from './ProcessingMenu';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
});

class Playbooks extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'playbooks-view',
    );
    this.state = {
      orderAsc: propOr(true, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'playbooks-view',
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc, searchTerm } = this.state;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '30%',
        isSortable: true,
      },
      description: {
        label: 'Description',
        width: '50%',
        isSortable: true,
      },
      playbook_running: {
        label: 'Running',
        width: '15%',
        isSortable: false,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        handleSearch={this.handleSearch.bind(this)}
        displayImport={false}
        secondaryAction={true}
        keyword={searchTerm}
      >
        <QueryRenderer
          query={PlaybooksLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <PlaybooksLines
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
    const { classes } = this.props;
    const { view, sortBy, orderAsc, searchTerm } = this.state;
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        <ProcessingMenu />
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <PlaybookCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

Playbooks.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(
  inject18n,
  withTheme,
  withRouter,
  withStyles(styles),
)(Playbooks);
