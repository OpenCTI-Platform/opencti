import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { PortWidget } from 'storm-react-diagrams';
import { withStyles } from '@material-ui/core/styles';
import IconButton from '@material-ui/core/IconButton';
import { Info, OpenWith } from '@material-ui/icons';
import { Link } from 'react-router-dom';
import { truncate } from '../../utils/String';
import { itemColor } from '../../utils/Colors';
import { resolveLink } from '../../utils/Entity';
import ItemIcon from '../ItemIcon';

const styles = () => ({
  node: {
    position: 'relative',
    width: 150,
    height: 60,
    borderRadius: 10,
    zIndex: 20,
    padding: '10px 0 10px 0',
  },
  port: {
    position: 'absolute',
    width: 180,
    height: 80,
    top: 0,
    left: 0,
    borderRadius: 10,
  },
  content: {
    width: '100%',
    color: '#ffffff',
    textAlign: 'center',
  },
  name: {
    display: 'inline-block',
    lineHeight: 1,
    fontSize: 12,
    verticalAlign: 'middle',
  },
  overlay: {
    transition: 'opacity 600ms, visibility 600ms;',
    position: 'absolute',
    opacity: 0,
    visibility: 'hidden',
    top: 10,
    left: -40,
  },
  button: {
    padding: 5,
  },
});

class EntityNodeWidget extends Component {
  setSelected() {
    this.props.node.setSelected(true);
    this.forceUpdate();
  }

  handleExpand() {
    this.props.node.setSelected(true, true);
  }

  render() {
    const {
      node, node: { extras, expandable }, classes,
    } = this.props;
    const link = resolveLink(extras.type);
    return (
      <div className={classes.node} style={{
        backgroundColor: itemColor(extras.type, true),
        border: node.selected ? '2px solid #00c0ff' : '2px solid #333333',
        display: node.hidden ? 'none' : 'block',
      }}>
        <div className={classes.content}>
          <ItemIcon type={extras.type} color={itemColor(extras.type, false)} size='large'/>
          <br/>
          <span className={classes.name}>{truncate(extras.name, 50)}</span>
        </div>
        <div className={classes.overlay} style={{ visibility: node.selected ? 'visible' : 'hidden', opacity: node.selected ? 1 : 0 }}>
          <IconButton component={Link} to={`${link}/${extras.id}`} className={classes.button} style={{ marginTop: expandable ? 0 : 15 }}>
            <Info fontSize='small'/>
          </IconButton>
          <br/>
          {expandable ? <IconButton onClick={this.handleExpand.bind(this)} className={classes.button}>
            <OpenWith fontSize='small'/>
          </IconButton> : ''}
        </div>
        <div className={classes.port} onClick={this.setSelected.bind(this)} style={{ display: node.selected ? 'none' : 'block' }}>
          <PortWidget name='main' node={node}/>
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

export default withStyles(styles)(EntityNodeWidget);
