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
import NarrativesLines, {
  narrativesLinesQuery,
} from './narratives/NarrativesLines';
import NarrativeCreation from './narratives/NarrativeCreation';
import SearchInput from '../../../components/SearchInput';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';

export const narrativesSearchQuery = graphql`
  query NarrativesSearchQuery($search: String) {
    narratives(search: $search) {
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

class Narratives extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-narratives',
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
      'view-narratives',
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
          query={narrativesLinesQuery}
          variables={{ count: 500 }}
          render={({ props }) => (
            <NarrativesLines data={props} keyword={searchTerm} />
          )}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <NarrativeCreation />
        </Security>
      </div>
    );
  }
}

Narratives.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(Narratives);
