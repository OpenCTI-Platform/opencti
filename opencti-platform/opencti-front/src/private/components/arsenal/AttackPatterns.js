import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { graphql } from 'react-relay';
import { withRouter } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import AttackPatternsLines, {
  attackPatternsLinesQuery,
} from './attack_patterns/AttackPatternsLines';
import AttackPatternCreation from './attack_patterns/AttackPatternCreation';
import SearchInput from '../../../components/SearchInput';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';

export const attackPatternsSearchQuery = graphql`
  query AttackPatternsSearchQuery($search: String) {
    attackPatterns(search: $search) {
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

class AttackPatterns extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-attack_patterns',
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
      'view-attack_patterns',
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
          query={attackPatternsLinesQuery}
          variables={{ count: 1500 }}
          render={({ props }) => (
            <AttackPatternsLines data={props} keyword={searchTerm} />
          )}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AttackPatternCreation />
        </Security>
      </div>
    );
  }
}

AttackPatterns.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(AttackPatterns);
