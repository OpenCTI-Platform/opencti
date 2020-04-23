import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRightOutlined, DomainOutlined } from '@material-ui/icons';
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

class SectorLineComponent extends Component {
  render() {
    const {
      classes, subSectors, node, isSubSector, t,
    } = this.props;
    return (
      <div>
        <ListItem
          classes={{ root: isSubSector ? classes.itemNested : classes.item }}
          divider={true}
          button={true}
          component={Link}
          to={`/dashboard/entities/sectors/${node.id}`}
        >
          <ListItemIcon classes={{ root: classes.itemIcon }}>
            <DomainOutlined fontSize={isSubSector ? 'small' : 'default'} />
          </ListItemIcon>
          <ListItemText
            primary={
              <div>
                <div
                  className={classes.name}
                  style={{ fontSize: isSubSector ? 11 : 13 }}
                >
                  {node.name}
                </div>
                <div
                  className={classes.description}
                  style={{ fontSize: isSubSector ? 11 : 13 }}
                >
                  {node.description.length > 0
                    ? node.description
                    : t('This sector does not have any description.')}
                </div>
              </div>
            }
          />
          <ListItemIcon classes={{ root: classes.goIcon }}>
            <KeyboardArrowRightOutlined />
          </ListItemIcon>
        </ListItem>
        {subSectors ? (
          <List disablePadding={true}>
            {map(
              (subSector) => (
                <SectorLine
                  key={subSector.id}
                  node={subSector}
                  isSubSector={true}
                />
              ),
              subSectors,
            )}
          </List>
        ) : (
          ''
        )}
      </div>
    );
  }
}

SectorLineComponent.propTypes = {
  node: PropTypes.object,
  isSubSector: PropTypes.bool,
  subSectors: PropTypes.array,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

export const SectorLine = compose(
  inject18n,
  withStyles(styles),
)(SectorLineComponent);

class SectorLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <DomainOutlined />
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

SectorLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const SectorLineDummy = compose(
  inject18n,
  withStyles(styles),
)(SectorLineDummyComponent);
