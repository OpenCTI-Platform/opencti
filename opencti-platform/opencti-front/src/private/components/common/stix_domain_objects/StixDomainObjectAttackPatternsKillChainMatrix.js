import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import AttackPatternsMatrix from '../../arsenal/attack_patterns/AttackPatternsMatrix';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class StixDomainObjectAttackPatternsKillChainMatrix extends Component {
  render() {
    const { searchTerm, data } = this.props;
    const attackPatterns = R.map(
      (n) => n.node.to,
      data.stixCoreRelationships.edges,
    );
    return (
      <AttackPatternsMatrix
        attackPatterns={attackPatterns}
        searchTerm={searchTerm}
        marginRight={true}
      />
    );
  }
}

StixDomainObjectAttackPatternsKillChainMatrix.propTypes = {
  data: PropTypes.object,
  searchTerm: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectAttackPatternsKillChainMatrix);
