import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Tooltip from '@material-ui/core/Tooltip';
import { PortWidget } from 'storm-react-diagrams';
import inject18n from '../i18n';

const styles = () => ({
  node: {
    position: 'relative',
    textAlign: 'center',
    width: 70,
    height: 30,
    lineHeight: '30px',
    zIndex: 20,
    borderRadius: 10,
    fontSize: 11,
    backgroundColor: '#303030',
  },
  portContainer: {
    position: 'absolute',
    top: 0,
    left: 0,
    width: '100%',
    height: '100%',
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
      <Tooltip
        title={
          extras.first_seen ? (
            <span>
              {t('First obs.')} {nsd(extras.first_seen)}
              <br />
              {t('Last obs.')} {nsd(extras.last_seen)}
            </span>
          ) : (
            ''
          )
        }
        aria-label="add"
      >
        <div
          className={classes.node}
          style={{
            border: node.selected ? '2px solid #00c0ff' : '2px solid #ff3d00',
          }}
        >
          <strong>{t(`relation_${extras.relationship_type}`)}</strong>
          <div
            className={classes.portContainer}
            style={{ display: node.selected ? 'none' : 'block' }}
            onClick={this.setSelected.bind(this)}
          >
            <PortWidget name="main" node={node} />
          </div>
        </div>
      </Tooltip>
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
