import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import Markdown from 'react-markdown';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

class ThreatActorIdentityComponent extends Component {
  render() {
    const {
      t, classes, threatActor,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Identity')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant='h3' gutterBottom={true}>
            {t('Sophistication')}
          </Typography>
          {t(`${threatActor.sophistication ? `sophistication_${threatActor.sophistication}` : 'sophistication_unkown'}`)}
          <Typography variant='h3' gutterBottom={true} style={{ marginTop: 20 }}>
            {t('Resource level')}
          </Typography>
          {t(`${threatActor.resource_level ? `resource_${threatActor.resource_level}` : 'resource_unkown'}`)}
          <Typography variant='h3' gutterBottom={true} style={{ marginTop: 20 }}>
            {t('Primary motivation')}
          </Typography>
          {t(`${threatActor.primary_motivation ? `motivation_${threatActor.primary_motivation}` : 'motivation_unpredictable'}`)}
          <Typography variant='h3' gutterBottom={true} style={{ marginTop: 20 }}>
            {t('Secondary motivation')}
          </Typography>
          {t(`${threatActor.secondary_motivation ? `motivation_${threatActor.secondary_motivation}` : 'motivation_unknown'}`)}
          <Typography variant='h3' gutterBottom={true} style={{ marginTop: 20 }}>
            {t('Goal')}
          </Typography>
          <Markdown className='markdown' source={threatActor.goal}/>
          </Paper>
      </div>
    );
  }
}

ThreatActorIdentityComponent.propTypes = {
  threatActor: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ThreatActorIdentity = createFragmentContainer(ThreatActorIdentityComponent, {
  threatActor: graphql`
      fragment ThreatActorIdentity_threatActor on ThreatActor {
          id
          sophistication
          resource_level
          primary_motivation
          secondary_motivation
          goal
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(ThreatActorIdentity);
