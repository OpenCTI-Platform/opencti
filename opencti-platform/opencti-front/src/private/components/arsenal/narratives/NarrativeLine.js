import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import {
  KeyboardArrowRightOutlined,
  SpeakerNotesOutlined,
} from '@mui/icons-material';
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
    height: '.6em',
    backgroundColor: theme.palette.grey[700],
  },
});

class NarrativeLineComponent extends Component {
  render() {
    const { classes, subNarratives, node, isSubNarrative, t } = this.props;
    return (
      <div>
        <ListItem
          classes={{ root: isSubNarrative ? classes.itemNested : classes.item }}
          divider={true}
          button={true}
          component={Link}
          to={`/dashboard/arsenal/narratives/${node.id}`}
        >
          <ListItemIcon classes={{ root: classes.itemIcon }}>
            <SpeakerNotesOutlined
              fontSize={isSubNarrative ? 'small' : 'medium'}
            />
          </ListItemIcon>
          <ListItemText
            primary={
              <div>
                <div className={classes.name}>{node.name}</div>
                <div className={classes.description}>
                  {node.description?.length > 0
                    ? node.description
                    : t('This narrative does not have any description.')}
                </div>
              </div>
            }
          />
          <ListItemIcon classes={{ root: classes.goIcon }}>
            <KeyboardArrowRightOutlined />
          </ListItemIcon>
        </ListItem>
        {subNarratives && subNarratives.length > 0 && (
          <List style={{ margin: 0, padding: 0 }}>
            {map(
              (subNarrative) => (
                // eslint-disable-next-line @typescript-eslint/no-use-before-define
                <NarrativeLine
                  key={subNarrative.id}
                  node={subNarrative}
                  isSubNarrative={true}
                />
              ),
              subNarratives,
            )}
          </List>
        )}
      </div>
    );
  }
}

NarrativeLineComponent.propTypes = {
  node: PropTypes.object,
  isSubNarrative: PropTypes.bool,
  subNarratives: PropTypes.array,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

export const NarrativeLine = compose(
  inject18n,
  withStyles(styles),
)(NarrativeLineComponent);

class NarrativeLineDummyComponent extends Component {
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

NarrativeLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const NarrativeLineDummy = compose(
  inject18n,
  withStyles(styles),
)(NarrativeLineDummyComponent);
