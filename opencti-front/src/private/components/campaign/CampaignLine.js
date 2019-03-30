import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight } from '@material-ui/icons';
import { ChessKnight } from 'mdi-material-ui';
import { compose } from 'ramda';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    fontSize: 13,
  },
  goIcon: {
    position: 'absolute',
    right: 10,
    marginRight: 0,
  },
  itemIconDisabled: {
    color: theme.palette.text.disabled,
  },
});

const inlineStyles = {
  name: {
    float: 'left',
    width: '70%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  modified: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class CampaignLineComponent extends Component {
  render() {
    const { fd, classes, campaign } = this.props;
    return (
      <ListItem
        classes={{ default: classes.item }}
        divider={true}
        component={Link}
        to={`/dashboard/knowledge/campaigns/${campaign.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ChessKnight />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                {campaign.name}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(campaign.created)}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.modified}>
                {fd(campaign.modified)}
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItem>
    );
  }
}

CampaignLineComponent.propTypes = {
  campaign: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const CampaignLineFragment = createFragmentContainer(CampaignLineComponent, {
  campaign: graphql`
    fragment CampaignLine_campaign on Campaign {
      id
      name
      created
      modified
    }
  `,
});

export const CampaignLine = compose(
  inject18n,
  withStyles(styles),
)(CampaignLineFragment);

class CampaignLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <ChessKnight />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.modified}>
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItem>
    );
  }
}

CampaignLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const CampaignLineDummy = compose(
  inject18n,
  withStyles(styles),
)(CampaignLineDummyComponent);
