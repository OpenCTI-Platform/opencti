import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Tooltip from '@material-ui/core/Tooltip';
import { PortWidget } from 'storm-react-diagrams';
import IconButton from '@material-ui/core/IconButton';
import { Delete, Edit } from '@material-ui/icons';
import inject18n from '../i18n';

const styles = () => ({
  node: {
    position: 'relative',
    width: 70,
    height: 25,
    zIndex: 20,
    borderRadius: 10,
    backgroundColor: '#303030',
  },
  label: {
    wdith: '100%',
    lineHeight: '25px',
    fontSize: 11,
    textAlign: 'center',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  port: {
    position: 'absolute',
    top: 0,
    left: 0,
    width: '100%',
    height: '100%',
    border: 1,
    overflow: 'hidden',
    borderRadius: 10,
  },
  actions: {
    display: 'flex',
    position: 'absolute',
    top: -25,
    left: 12,
    width: 50,
    zIndex: 300,
    justifyContent: 'space-between',
  },
});

class RelationNodeWidget extends Component {
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
            border: node.selected ? '2px solid #00c0ff' : '2px solid #9e9e9e',
          }}
        >
          <div className={classes.label}>
            <strong>{t(`relation_${extras.type}`)}</strong>
          </div>
          <div
            className={classes.port}
            style={{ display: node.selected ? 'none' : 'block' }}
            onClick={this.setSelected.bind(this)}
          >
            <PortWidget name="main" node={node} />
          </div>
          {node.selected ? (
            <div className={classes.actions}>
              <IconButton
                aria-label="edit"
                size="small"
                onClick={this.handleEdit.bind(this, node)}
              >
                <Edit fontSize="small" />
              </IconButton>
              <IconButton
                aria-label="delete"
                size="small"
                onClick={this.handleRemove.bind(this, node)}
              >
                <Delete fontSize="small" />
              </IconButton>
            </div>
          ) : (
            ''
          )}
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
