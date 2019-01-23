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
    height: 80,
    borderRadius: 10,
    zIndex: 20,
  },
  port: {
    position: 'absolute',
    width: 180,
    height: 80,
    top: 0,
    left: 0,
    borderRadius: 10,
  },
  header: {
    padding: '10px 0 10px 0',
    borderBottom: '1px solid #ffffff',
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
  setSelected() {
    this.props.node.setSelected(true);
    this.forceUpdate();
  }

  render() {
    const {
      node, node: { extras }, classes, t,
    } = this.props;
    return (
      <div className={classes.node} style={{
        backgroundColor: itemColor(extras.type, true),
        border: node.selected ? '2px solid #00c0ff' : '2px solid #333333',
      }}>
        <div className={classes.header}>
            <div className={classes.icon}>
              <ItemIcon type={extras.type} color={itemColor(extras.type, false)} size='small'/>
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
        <div className={classes.port} onClick={this.setSelected.bind(this)} style={{ display: node.selected ? 'none' : 'block' }}>
          <PortWidget name='main' node={node} />
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
