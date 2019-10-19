import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { PortWidget } from 'storm-react-diagrams';
import { withStyles } from '@material-ui/core/styles';
import { itemColor } from '../../utils/Colors';
import ItemIcon from '../ItemIcon';

const styles = () => ({
  node: {
    position: 'relative',
    width: 80,
    height: 80,
    zIndex: 20,
    borderRadius: '50%',
    backgroundColor: '#303030',
  },
  circle: {
    position: 'absolute',
    top: 10,
    left: 10,
    width: 60,
    height: 60,
    zIndex: 20,
    borderRadius: '50%',
  },
  icon: {
    margin: '0 auto',
    textAlign: 'center',
    paddingTop: 10,
  },
  nameContainer: {
    position: 'absolute',
    top: 85,
    left: '50%',
    width: 120,
    color: '#ffffff',
    textAlign: 'center',
  },
  name: {
    position: 'relative',
    left: '-50%',
    width: '100%',
    textAlign: 'center',
  },
  portContainer: {
    position: 'absolute',
    top: -2,
    left: -2,
    padding: 0,
    width: 80,
    height: 80,
    border: 1,
    overflow: 'hidden',
  },
});

class EntityNodeWidget extends Component {
  setSelected() {
    this.props.node.setSelected(true);
    this.forceUpdate();
  }

  render() {
    const {
      node,
      node: { extras },
      classes,
    } = this.props;
    return (
      <div className={classes.node}>
        <div
          className={classes.circle}
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
          <div
            className={classes.portContainer}
            style={{ display: node.selected ? 'none' : 'block' }}
            onClick={this.setSelected.bind(this)}
          >
            <PortWidget name="main" node={node} />
          </div>
        </div>
        <div className={classes.nameContainer}>
          <div className={classes.name}>{extras.name}</div>
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
