import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import RegionsLines, { regionsLinesQuery } from './regions/RegionsLines';
import RegionCreation from './regions/RegionCreation';
import SearchInput from '../../../components/SearchInput';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';

export const regionsSearchQuery = graphql`
  query RegionsSearchQuery($search: String) {
    regions(search: $search) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const styles = () => ({
  parameters: {
    float: 'left',
    marginTop: -10,
  },
});

class Regions extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-regions',
    );
    this.state = {
      searchTerm: propOr('', 'searchTerm', params),
      openExports: false,
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-regions',
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports });
  }

  render() {
    const { searchTerm } = this.state;
    const { classes } = this.props;
    return (
      <div>
        <div className={classes.parameters}>
          <div style={{ float: 'left', marginRight: 20 }}>
            <SearchInput
              variant="small"
              onSubmit={this.handleSearch.bind(this)}
              keyword={searchTerm}
            />
          </div>
        </div>
        <div className="clearfix" />
        <QueryRenderer
          query={regionsLinesQuery}
          variables={{ count: 500 }}
          render={({ props }) => (
            <RegionsLines data={props} keyword={searchTerm} />
          )}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <RegionCreation />
        </Security>
      </div>
    );
  }
}

Regions.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(Regions);
