import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { PortWidget } from 'storm-react-diagrams';
import { withStyles } from '@material-ui/core/styles';
import IconButton from '@material-ui/core/IconButton';
import { Edit, Delete, Info } from '@material-ui/icons';
import { itemColor } from '../../utils/Colors';
import { resolveLink } from '../../utils/Entity';
import ItemIcon from '../ItemIcon';

const styles = () => ({
  node: {
    position: 'relative',
    width: 60,
    height: 60,
    zIndex: 20,
    borderRadius: '50%',
    backgroundColor: '#303030',
  },
  icon: {
    margin: '0 auto',
    textAlign: 'center',
    paddingTop: 12,
  },
  name: {
    width: 120,
    position: 'absolute',
    left: -30,
    marginTop: 15,
    textAlign: 'center',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  port: {
    position: 'absolute',
    top: 0,
    left: 0,
    padding: 0,
    width: '100%',
    height: '100%',
    border: 1,
    overflow: 'hidden',
  },
  actions: {
    display: 'flex',
    position: 'absolute',
    top: -25,
    left: -10,
    width: 80,
    justifyContent: 'space-between',
  },
});

class EntityNodeWidget extends Component {
  setSelected() {
    this.props.node.setSelected(true);
    this.forceUpdate();
  }

  handleEdit() {
    this.props.node.setSelectedCustom(true, true);
  }

  handleRemove() {
    this.props.node.setSelectedCustom(true, false, true);
  }

  render() {
    const {
      node,
      node: { extras },
      classes,
    } = this.props;
    const link = resolveLink(extras.type);
    return (
      <div
        className={classes.node}
        style={{
          border: node.selected
            ? '2px solid #00c0ff'
            : `2px solid ${itemColor(extras.type, false)}`,
        }}
      >
        <div className={classes.icon}>
          <ItemIcon
            type={extras.type}
            color={itemColor(extras.type, false)}
            size="large"
          />
        </div>
        <div className={classes.name}>{extras.name}</div>
        <div
          className={classes.port}
          onClick={this.setSelected.bind(this)}
          style={{ display: node.selected ? 'none' : 'block' }}
        >
          <PortWidget name="main" node={node} />
        </div>
        {node.selected ? (
          <div className={classes.actions}>
            <IconButton
              aria-label="edit"
              size="small"
              onClick={this.handleEdit.bind(this, node)}
              disabled={extras.disabled === true}
            >
              <Edit fontSize="small" />
            </IconButton>
            <IconButton
              aria-label="delete"
              size="small"
              onClick={this.handleRemove.bind(this, node)}
              disabled={extras.disabled === true}
            >
              <Delete fontSize="small" />
            </IconButton>
            <IconButton
              aria-label="info"
              size="small"
              component={Link}
              target="_blank"
              to={`${link}/${extras.id}`}
            >
              <Info fontSize="small" />
            </IconButton>
          </div>
        ) : (
          ''
        )}
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
