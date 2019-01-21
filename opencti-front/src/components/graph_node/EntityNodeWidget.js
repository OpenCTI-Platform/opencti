import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { PortWidget } from 'storm-react-diagrams';
import { withStyles } from '@material-ui/core/styles';
import { MoreVert } from '@material-ui/icons';
import { itemColor } from '../../utils/Colors';
import inject18n from '../i18n';
import ItemIcon from '../ItemIcon';

const styles = () => ({
  node: {
    position: 'relative',
    width: 180,
    borderRadius: 10,
  },
  port: {
    position: 'absolute',
    zIndex: 10,
  },
  header: {
    padding: '10px 0 10px 0',
    borderBottom: '1px solid #AEAEAE',
  },
  icon: {
    position: 'absolute',
    top: 8,
    left: 5,
    fontSize: 8,
  },
  type: {
    width: '100%',
    textAlign: 'center',
    color: '#ffffff',
    fontSize: 11,
  },
  popover: {
    position: 'absolute',
    color: '#ffffff',
    top: 8,
    right: 5,
  },
  content: {
    width: '100%',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: '#ffffff',
    textAlign: 'center',
  },
  name: {
    display: 'inline-block',
    lineHeight: 1,
    fontSize: 12,
    verticalAlign: 'middle',
  },
});

class EntityNodeWidget extends Component {
  constructor(props) {
    super(props);
    this.state = {};
  }

  render() {
    const {
      node, node: { extras }, classes, t,
    } = this.props;

    return (
      <div className={classes.node} style={{
        backgroundColor: itemColor(extras.type, 0.7),
        border: node.selected ? '2px solid #2d4b5b' : '2px solid #333333',
      }}>
        <div className={classes.header}>
            <div className={classes.icon}>
              <ItemIcon type={extras.type} color={itemColor(extras.type, 1)} size='small'/>
            </div>
            <div className={classes.type}>
              {t(`entity_${extras.type}`)}
            </div>
            <div className={classes.popover}>
              <MoreVert fontSize='small' />
            </div>
        </div>
        <div className={classes.content}>
          <span className={classes.name}>{extras.name}</span>
        </div>
        <div className={classes.port} style={{ top: 35, left: -8 }}>
          <PortWidget name='left' node={node} />
        </div>
        <div className={classes.port} style={{ top: 35, right: -8 }}>
          <PortWidget name='right' node={node} />
        </div>
        <div className={classes.port} style={{ top: -8, left: 84 }}>
          <PortWidget name='top' node={node} />
        </div>
        <div className={classes.port} style={{ bottom: -8, left: 84 }}>
          <PortWidget name='bottom' node={node} />
        </div>
      </div>
    );
  }
}

EntityNodeWidget.propTypes = {
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityNodeWidget);
