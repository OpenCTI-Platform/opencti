import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import Markdown from 'react-markdown';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Card from '@material-ui/core/Card';
import CardActionArea from '@material-ui/core/CardActionArea';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import Avatar from '@material-ui/core/Avatar';
import { compose } from 'ramda';
import { ChessKnight } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  card: {
    width: '100%',
    height: 170,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
  cardDummy: {
    width: '100%',
    height: 170,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.disabled,
    borderRadius: 6,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    backgroundColor: theme.palette.text.disabled,
  },
  icon: {
    margin: '10px 20px 0 0',
    fontSize: 40,
    color: '#242d30',
  },
  area: {
    width: '100%',
    height: '100%',
  },
  header: {
    paddingBottom: 0,
    marginBottom: 0,
  },
  content: {
    width: '100%',
    height: 89,
    overflow: 'hidden',
    paddingTop: 0,
    fontSize: 15,
  },
  contentDummy: {
    width: '100%',
    height: 89,
    overflow: 'hidden',
    marginTop: 15,
  },
  placeholderHeader: {
    display: 'inline-block',
    height: '.8em',
    backgroundColor: theme.palette.text.disabled,
  },
  placeholderHeaderDark: {
    display: 'inline-block',
    height: '.8em',
    backgroundColor: theme.palette.text.disabledDark,
  },
});

class CampaignCardComponent extends Component {
  render() {
    const {
      t, fsd, classes, campaign,
    } = this.props;
    return (
      <Card classes={{ root: classes.card }} raised={true}>
        <CardActionArea classes={{ root: classes.area }} component={Link} to={`/dashboard/knowledge/campaigns/${campaign.id}`}>
          <CardHeader
            classes={{ root: classes.header }}
            avatar={<Avatar className={classes.avatar}>{campaign.name.charAt(0)}</Avatar>}
            title={campaign.name}
            subheader={`${t('Updated the')} ${fsd(campaign.modified)}`}
            action={<ChessKnight className={classes.icon}/>}
          />
          <CardContent classes={{ root: classes.content }}>
            <Markdown source={campaign.description} disallowedTypes={['link']} unwrapDisallowed={true}/>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

CampaignCardComponent.propTypes = {
  campaign: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
};

const CampaignCardFragment = createFragmentContainer(CampaignCardComponent, {
  campaign: graphql`
      fragment CampaignCard_campaign on Campaign {
          id
          name
          description
          created
          modified
      }
  `,
});

export const CampaignCard = compose(
  inject18n,
  withStyles(styles),
)(CampaignCardFragment);


class CampaignCardDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <Card classes={{ root: classes.cardDummy }} raised={true}>
        <CardActionArea classes={{ root: classes.area }}>
          <CardHeader
            classes={{ root: classes.header }}
            avatar={<Avatar className={classes.avatarDisabled}>D</Avatar>}
            title={<div className={classes.placeholderHeader} style={{ width: '85%' }}/>}
            titleTypographyProps={{ color: 'inherit' }}
            subheader={<div className={classes.placeholderHeaderDark} style={{ width: '70%' }}/>}
            action={<ChessKnight className={classes.icon}/>}
          />
          <CardContent classes={{ root: classes.contentDummy }}>
            <div className='fakeItem' style={{ width: '90%' }}/>
            <div className='fakeItem' style={{ width: '95%' }}/>
            <div className='fakeItem' style={{ width: '90%' }}/>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

CampaignCardDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const CampaignCardDummy = compose(
  inject18n,
  withStyles(styles),
)(CampaignCardDummyComponent);
