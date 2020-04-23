import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRightOutlined, MapOutlined } from '@material-ui/icons';
import { compose, map } from 'ramda';
import List from '@material-ui/core/List';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  item: {},
  itemNested: {
    paddingLeft: theme.spacing(4),
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  name: {
    width: '20%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  description: {
    width: '70%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    color: '#a5a5a5',
  },
  goIcon: {
    position: 'absolute',
    right: 10,
    marginRight: 0,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '.6em',
    backgroundColor: theme.palette.grey[700],
  },
});

class RegionLineComponent extends Component {
  render() {
    const {
      classes, subRegions, node, isSubRegion, t,
    } = this.props;
    return (
      <div>
        <ListItem
          classes={{ root: isSubRegion ? classes.itemNested : classes.item }}
          divider={true}
          button={true}
          component={Link}
          to={`/dashboard/entities/regions/${node.id}`}
        >
          <ListItemIcon classes={{ root: classes.itemIcon }}>
            <MapOutlined fontSize={isSubRegion ? 'small' : 'default'} />
          </ListItemIcon>
          <ListItemText
            primary={
              <div>
                <div
                  className={classes.name}
                  style={{ fontSize: isSubRegion ? 11 : 13 }}
                >
                  {node.name}
                </div>
                <div
                  className={classes.description}
                  style={{ fontSize: isSubRegion ? 11 : 13 }}
                >
                  {node.description.length > 0
                    ? node.description
                    : t('This region does not have any description.')}
                </div>
              </div>
            }
          />
          <ListItemIcon classes={{ root: classes.goIcon }}>
            <KeyboardArrowRightOutlined />
          </ListItemIcon>
        </ListItem>
        {subRegions ? (
          <List disablePadding={true}>
            {map(
              (subRegion) => (
                <RegionLine
                  key={subRegion.id}
                  node={subRegion}
                  isSubRegion={true}
                />
              ),
              subRegions,
            )}
          </List>
        ) : (
          ''
        )}
      </div>
    );
  }
}

RegionLineComponent.propTypes = {
  node: PropTypes.object,
  isSubRegion: PropTypes.bool,
  subRegions: PropTypes.array,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

export const RegionLine = compose(
  inject18n,
  withStyles(styles),
)(RegionLineComponent);

class RegionLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <MapOutlined />
        </ListItemIcon>
        <ListItemText
          primary={<span className="fakeItem" style={{ width: '80%' }} />}
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

RegionLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const RegionLineDummy = compose(
  inject18n,
  withStyles(styles),
)(RegionLineDummyComponent);
