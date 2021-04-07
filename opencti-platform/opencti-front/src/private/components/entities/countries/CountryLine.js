import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRightOutlined, FlagOutlined } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  item: {
    paddingLeft: theme.spacing(8),
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  text: {
    fontSize: 12,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class CountryLineComponent extends Component {
  render() {
    const { classes, node } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/entities/countries/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <FlagOutlined />
        </ListItemIcon>
        <ListItemText classes={{ primary: classes.text }} primary={node.name} />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

CountryLineComponent.propTypes = {
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

export const CountryLine = compose(
  inject18n,
  withStyles(styles),
)(CountryLineComponent);

class CountryLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <FlagOutlined />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.modified.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

CountryLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const CountryLineDummy = compose(
  inject18n,
  withStyles(styles),
)(CountryLineDummyComponent);
