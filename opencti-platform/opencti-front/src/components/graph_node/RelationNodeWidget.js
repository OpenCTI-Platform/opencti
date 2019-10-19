import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { PortWidget } from 'storm-react-diagrams';
import inject18n from '../i18n';

const styles = () => ({
  node: {
    position: 'relative',
    textAlign: 'center',
    padding: '5px 8px 5px 8px',
    backgroundColor: '#14262c',
    width: 70,
    height: 50,
    zIndex: 20,
    borderRadius: 10,
  },
  portContainer: {
    position: 'absolute',
    top: 0,
    left: 0,
    padding: '5px 8px 5px 8px',
    width: 70,
    height: 50,
    border: 1,
    overflow: 'hidden',
    borderRadius: 10,
  },
});

class RelationNodeWidget extends Component {
  setSelected() {
    this.props.node.setSelected(true);
    this.forceUpdate();
  }

  render() {
    const {
      node,
      node: { extras },
      classes,
      t,
      nsd,
    } = this.props;
    return (
      <div
        className={classes.node}
        style={{
          border: node.selected ? '2px solid #00c0ff' : '2px solid #ff3d00',
        }}
      >
        <strong>{t(`relation_${extras.relationship_type}`)}</strong>
        {extras.first_seen ? (
          <span>
            <br />
            {nsd(extras.first_seen)}
            <br />
            {nsd(extras.last_seen)}
          </span>
        ) : (
          ''
        )}
        <div
          className={classes.portContainer}
          style={{ display: node.selected ? 'none' : 'block' }}
          onClick={this.setSelected.bind(this)}
        >
          <PortWidget name="main" node={node} />
        </div>
      </div>
    );
  }
}

RelationNodeWidget.propTypes = {
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(RelationNodeWidget);
