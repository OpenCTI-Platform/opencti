import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import withRouter from '../../../../utils/compat-router/withRouter';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Loader from '../../../../components/Loader';
import AttackPatternsMatrixColumns, { attackPatternsMatrixColumnsQuery } from './AttackPatternsMatrixColumns';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
});

class AttackPatternsMatrix extends Component {
  render() {
    const {
      classes,
      attackPatterns,
      marginRight,
      searchTerm,
      handleToggleModeOnlyActive,
      handleToggleColorsReversed,
      currentColorsReversed,
      currentModeOnlyActive,
      hideBar,
      handleAdd,
    } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={attackPatternsMatrixColumnsQuery}
          variables={{
            count: 5000,
            filters: {
              mode: 'and',
              filters: [{ key: 'revoked', values: ['false'] }],
              filterGroups: [],
            },
          }}
          render={({ props }) => {
            if (props) {
              return (
                <AttackPatternsMatrixColumns
                  data={props}
                  attackPatterns={attackPatterns}
                  marginRight={marginRight}
                  searchTerm={searchTerm ?? ''}
                  handleToggleModeOnlyActive={handleToggleModeOnlyActive}
                  handleToggleColorsReversed={handleToggleColorsReversed}
                  currentColorsReversed={currentColorsReversed}
                  currentModeOnlyActive={currentModeOnlyActive}
                  hideBar={hideBar}
                  handleAdd={handleAdd}
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
  marginRight: PropTypes.bool,
  navigate: PropTypes.func,
  location: PropTypes.object,
  classes: PropTypes.object,
  attackPatterns: PropTypes.array,
  searchTerm: PropTypes.string,
  handleToggleModeOnlyActive: PropTypes.func,
  handleToggleColorsReversed: PropTypes.func,
  currentColorsReversed: PropTypes.bool,
  currentModeOnlyActive: PropTypes.bool,
  hideBar: PropTypes.bool,
  handleAdd: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(AttackPatternsMatrix);
