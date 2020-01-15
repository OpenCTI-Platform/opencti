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
import SectorsLines, { sectorsLinesQuery } from './sectors/SectorsLines';
import SectorCreation from './sectors/SectorCreation';
import SearchInput from '../../../components/SearchInput';

export const sectorsSearchQuery = graphql`
  query SectorsSearchQuery($search: String) {
    sectors(search: $search) {
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

class Sectors extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'Sectors-view',
    );
    this.state = {
      searchTerm: propOr('', 'searchTerm', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'Sectors-view',
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
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
          query={sectorsLinesQuery}
          variables={{ count: 500 }}
          render={({ props }) => (
            <SectorsLines data={props} keyword={searchTerm} />
          )}
        />
        <SectorCreation />
      </div>
    );
  }
}

Sectors.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(Sectors);
