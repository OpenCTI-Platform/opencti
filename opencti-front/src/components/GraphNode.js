import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import { compose } from 'ramda';
import Avatar from '@material-ui/core/Avatar';
import inject18n from './i18n';
import ItemIcon from './ItemIcon';

const styles = () => ({
  node: {
    width: '100%',
    height: '100%',
    backgroundColor: '#000000',
    color: '#ffffff',
  },
});

class GraphNode extends Component {
  render() {
    const { node, classes, t } = this.props;
    console.log(node);
    return (
      <div className={classes.node}>
        {node.name}
      </div>
    );
  }
}

GraphNode.propTypes = {
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(GraphNode);
