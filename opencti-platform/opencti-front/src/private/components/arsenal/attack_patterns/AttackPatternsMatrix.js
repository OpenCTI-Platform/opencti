import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core';
import { QueryRenderer } from '../../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import inject18n from '../../../../components/i18n';
import Loader from '../../../../components/Loader';
import AttackPatternsMatrixColumns, {
  attackPatternsMatrixColumnsQuery,
} from './AttackPatternsMatrixColumns';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
});

class AttackPatternsMatrix extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-entity-${this.props.entity.id}-matrix`,
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
      `view-entity-${this.props.entity.id}-matrix`,
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  render() {
    const { classes, attackPatterns } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={attackPatternsMatrixColumnsQuery}
          variables={{
            count: 1500,
            filters: [{ key: 'revoked', values: ['false'] }],
          }}
          render={({ props }) => {
            if (props) {
              return (
                <AttackPatternsMatrixColumns
                  data={props}
                  attackPatterns={attackPatterns}
                />
              );
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

AttackPatternsMatrix.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
  attackPatterns: PropTypes.array,
  entity: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(AttackPatternsMatrix);
