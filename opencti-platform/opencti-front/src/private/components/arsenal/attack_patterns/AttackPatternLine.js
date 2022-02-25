import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { LockPattern } from 'mdi-material-ui';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import { compose, map } from 'ramda';
import List from '@mui/material/List';
import Skeleton from '@mui/material/Skeleton';
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
    right: -10,
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

class AttackPatternLineComponent extends Component {
  render() {
    const { classes, subAttackPatterns, node, isSubAttackPattern, t } = this.props;
    return (
      <div>
        <ListItem
          classes={{
            root: isSubAttackPattern ? classes.itemNested : classes.item,
          }}
          divider={true}
          button={true}
          component={Link}
          to={`/dashboard/arsenal/attack_patterns/${node.id}`}
        >
          <ListItemIcon classes={{ root: classes.itemIcon }}>
            <LockPattern fontSize={isSubAttackPattern ? 'small' : 'medium'} />
          </ListItemIcon>
          <ListItemText
            primary={
              <div>
                <div
                  className={classes.name}
                  style={{ fontSize: isSubAttackPattern ? 11 : 13 }}
                >
                  {node.x_mitre_id ? <strong>{node.x_mitre_id}</strong> : ''}
                  {node.x_mitre_id ? ' - ' : ''}
                  {node.name}
                </div>
                <div
                  className={classes.description}
                  style={{ fontSize: isSubAttackPattern ? 11 : 13 }}
                >
                  {node.description && node.description.length > 0
                    ? node.description
                    : t('This attack pattern does not have any description.')}
                </div>
              </div>
            }
          />
          <ListItemIcon classes={{ root: classes.goIcon }}>
            <KeyboardArrowRightOutlined />
          </ListItemIcon>
        </ListItem>
        {subAttackPatterns && (
          <List disablePadding={true}>
            {map(
              (subAttackPattern) => (
                // eslint-disable-next-line @typescript-eslint/no-use-before-define
                <AttackPatternLine
                  key={subAttackPattern.id}
                  node={subAttackPattern}
                  isSubAttackPattern={true}
                />
              ),
              subAttackPatterns,
            )}
          </List>
        )}
      </div>
    );
  }
}

AttackPatternLineComponent.propTypes = {
  node: PropTypes.object,
  isSubAttackPattern: PropTypes.bool,
  subAttackPatterns: PropTypes.array,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

export const AttackPatternLine = compose(
  inject18n,
  withStyles(styles),
)(AttackPatternLineComponent);

class AttackPatternLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              height={20}
            />
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

AttackPatternLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const AttackPatternLineDummy = compose(
  inject18n,
  withStyles(styles),
)(AttackPatternLineDummyComponent);
