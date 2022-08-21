import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import AttackPatternsMatrix from '../../arsenal/attack_patterns/AttackPatternsMatrix';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class StixDomainObjectAttackPatternsKillChainMatrix extends Component {
  render() {
    const {
      searchTerm,
      data,
      handleChangeKillChain,
      handleToggleModeOnlyActive,
      handleToggleColorsReversed,
      currentKillChain,
      currentColorsReversed,
      currentModeOnlyActive,
      handleAdd,
    } = this.props;
    const attackPatterns = R.map(
      (n) => (n.node.to.entity_type === 'Attack-Pattern' ? n.node.to : n.node.from),
      data.stixCoreRelationships.edges,
    );
    return (
      <AttackPatternsMatrix
        attackPatterns={attackPatterns}
        searchTerm={searchTerm}
        marginRight={true}
        handleChangeKillChain={handleChangeKillChain}
        handleToggleModeOnlyActive={handleToggleModeOnlyActive}
        handleToggleColorsReversed={handleToggleColorsReversed}
        currentKillChain={currentKillChain}
        currentColorsReversed={currentColorsReversed}
        currentModeOnlyActive={currentModeOnlyActive}
        hideBar={true}
        handleAdd={handleAdd}
      />
    );
  }
}

StixDomainObjectAttackPatternsKillChainMatrix.propTypes = {
  data: PropTypes.object,
  searchTerm: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  handleChangeKillChain: PropTypes.func,
  handleToggleModeOnlyActive: PropTypes.func,
  handleToggleColorsReversed: PropTypes.func,
  currentKillChain: PropTypes.bool,
  currentColorsReversed: PropTypes.bool,
  currentModeOnlyActive: PropTypes.bool,
  handleAdd: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectAttackPatternsKillChainMatrix);
