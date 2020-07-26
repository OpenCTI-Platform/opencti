import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Chip from '@material-ui/core/Chip';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import { Launch, SettingsApplications, PermIdentity } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import StixDomainObjectLabels from '../../common/stix_domain_objects/StixDomainObjectLabels';
import ItemCreator from '../../../../components/ItemCreator';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
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
          <Typography variant="h3" gutterBottom={true}>
            {t('External ID')}
          </Typography>
          <Chip
            size="small"
            label={attackPattern.x_mitre_id}
            color="primary"
            style={{ marginBottom: 20 }}
          />
          <StixDomainObjectLabels
            labels={attackPattern.labels}
            id={attackPattern.id}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creator')}
          </Typography>
          <ItemCreator creator={attackPattern.creator} />
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
                  divider={true}
                >
                  <ListItemIcon>
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
              <ListItem key={platform} dense={true} divider={true}>
                <ListItemIcon>
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
                <ListItem key={permission} dense={true} divider={true}>
                  <ListItemIcon>
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
        x_mitre_platforms
        x_mitre_permissions_required
        x_mitre_id
        creator {
          id
          name
        }
        labels {
          edges {
            node {
              id
              value
              color
            }
          }
        }
        killChainPhase {
          edges {
            node {
              id
              kill_chain_name
              phase_name
              x_opencti_order
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(AttackPatternDetails);
