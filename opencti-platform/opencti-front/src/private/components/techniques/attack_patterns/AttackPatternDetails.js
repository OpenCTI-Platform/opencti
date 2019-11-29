import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
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
import inject18n from '../../../../components/i18n';
import StixDomainEntityTags from '../../common/stix_domain_entities/StixDomainEntityTags';

const styles = () => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
});

class AttackPatternDetailsComponent extends Component {
  render() {
    const { t, classes, attackPattern } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <StixDomainEntityTags
            tags={attackPattern.tags}
            id={attackPattern.id}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Kill chain phases')}
          </Typography>
          <List>
            {attackPattern.killChainPhases.edges.map((killChainPhaseEdge) => {
              const killChainPhase = killChainPhaseEdge.node;
              return (
                <ListItem
                  key={killChainPhase.phase_name}
                  dense={true}
                  button={true}
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
            {propOr([], 'platform', attackPattern).map((platform) => (
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
              (permission) => (
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

AttackPatternDetailsComponent.propTypes = {
  attackPattern: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const AttackPatternDetails = createFragmentContainer(
  AttackPatternDetailsComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternDetails_attackPattern on AttackPattern {
        id
        platform
        required_permission
        tags {
          edges {
            node {
              id
              tag_type
              value
              color
            }
            relation {
              id
            }
          }
        }
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
)(AttackPatternDetails);
