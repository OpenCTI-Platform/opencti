import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import { compose } from 'ramda';
import Card from '@material-ui/core/Card';
import CardHeader from '@material-ui/core/CardHeader';
import Avatar from '@material-ui/core/Avatar';
import inject18n from './i18n';
import ItemIcon from './ItemIcon';

const styles = () => ({
  node: {
    width: '100%',
    height: '100%',
    backgroundColor: '#000000',
  },
});

class GraphNode extends Component {
  render() {
    const { node, classes, t } = this.props;
    console.log(node);
    return (
      <div className={classes.node}>
          <CardHeader
            classes={{ root: classes.header }}
            avatar={<Avatar className={classes.avatar}><ItemIcon type={node.entity_type}/></Avatar>}
            title={node.name}
            subheader={t(`entity_${node.entity_type}`)}
          />
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
