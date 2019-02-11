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
import { Fire } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import { truncate } from '../../../utils/String';

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
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.text.disabled,
  },
});

class IncidentCardComponent extends Component {
  render() {
    const {
      t, fsd, classes, incident,
    } = this.props;
    return (
      <Card classes={{ root: classes.card }} raised={true}>
        <CardActionArea classes={{ root: classes.area }} component={Link} to={`/dashboard/knowledge/incidents/${incident.id}`}>
          <CardHeader
            classes={{ root: classes.header }}
            avatar={<Avatar className={classes.avatar}>{incident.name.charAt(0)}</Avatar>}
            title={truncate(incident.name, 50)}
            subheader={`${t('Updated the')} ${fsd(incident.modified)}`}
            action={<Fire className={classes.icon}/>}
          />
          <CardContent classes={{ root: classes.content }}>
            <Markdown source={truncate(incident.description, 50)} disallowedTypes={['link']} unwrapDisallowed={true}/>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

IncidentCardComponent.propTypes = {
  incident: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
};

const IncidentCardFragment = createFragmentContainer(IncidentCardComponent, {
  incident: graphql`
      fragment IncidentCard_incident on Incident {
          id
          name
          description
          created
          modified
      }
  `,
});

export const IncidentCard = compose(
  inject18n,
  withStyles(styles),
)(IncidentCardFragment);


class IncidentCardDummyComponent extends Component {
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
            action={<Fire className={classes.icon}/>}
          />
          <CardContent classes={{ root: classes.contentDummy }}>
            <div className={classes.placeholder} style={{ width: '90%' }}/>
            <div className={classes.placeholder} style={{ width: '95%' }}/>
            <div className={classes.placeholder} style={{ width: '90%' }}/>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

IncidentCardDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const IncidentCardDummy = compose(
  inject18n,
  withStyles(styles),
)(IncidentCardDummyComponent);
