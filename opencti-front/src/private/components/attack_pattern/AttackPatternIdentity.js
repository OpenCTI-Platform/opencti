import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import { Launch, SettingsApplications, PermIdentity } from '@material-ui/icons';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
});

class AttackPatternIdentityComponent extends Component {
  render() {
    const { t, classes, attackPattern } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Identity')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Kill chain phases')}
          </Typography>
          <List>
            {attackPattern.killChainPhases.edges.map((killChainPhaseEdge) => {
              const killChainPhase = killChainPhaseEdge.node;
              return (
                <ListItem
                  key={killChainPhase.phase_name}
                  dense={true}
                  divider={true}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon classes={{ root: classes.itemIcon }}>
                    <Launch />
                  </ListItemIcon>
                  <ListItemText primary={killChainPhase.phase_name} />
                </ListItem>
              );
            })}
          </List>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Platforms')}
          </Typography>
          <List>
            {propOr([], 'platform', attackPattern).map(platform => (
              <ListItem
                key={platform}
                dense={true}
                divider={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <SettingsApplications />
                </ListItemIcon>
                <ListItemText primary={platform} />
              </ListItem>
            ))}
          </List>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Required permissions')}
          </Typography>
          <List>
            {propOr([], 'required_permission', attackPattern).map(
              permission => (
                <ListItem
                  key={permission}
                  dense={true}
                  divider={true}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon classes={{ root: classes.itemIcon }}>
                    <PermIdentity />
                  </ListItemIcon>
                  <ListItemText primary={permission} />
                </ListItem>
              ),
            )}
          </List>
        </Paper>
      </div>
    );
  }
}

AttackPatternIdentityComponent.propTypes = {
  attackPattern: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const AttackPatternIdentity = createFragmentContainer(
  AttackPatternIdentityComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternIdentity_attackPattern on AttackPattern {
        platform
        required_permission
        killChainPhases {
          edges {
            node {
              id
              kill_chain_name
              phase_name
              phase_order
            }
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(AttackPatternIdentity);
