import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Chip from '@mui/material/Chip';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { PermIdentity, SettingsApplications } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import AttackPatternParentAttackPatterns from './AttackPatternParentAttackPatterns';
import AttackPatternSubAttackPatterns from './AttackPatternSubAttackPatterns';
import AttackPatternCoursesOfAction from './AttackPatternCoursesOfAction';
import AttackPatternDataComponents from './AttackPatternDataComponents';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';

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
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              {attackPattern.isSubAttackPattern && (
                <AttackPatternParentAttackPatterns
                  attackPattern={attackPattern}
                />
              )}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: attackPattern.isSubAttackPattern ? 20 : 0 }}
              >
                {t('External ID')}
              </Typography>
              <Chip
                size="small"
                label={attackPattern.x_mitre_id}
                color="primary"
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Description')}
              </Typography>
              <ExpandableMarkdown
                source={attackPattern.description}
                limit={300}
              />
              <div>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ marginTop: 20 }}
                >
                  {t('Platforms')}
                </Typography>
                <List>
                  {propOr([], 'x_mitre_platforms', attackPattern).map(
                    (platform) => (
                      <ListItem key={platform} dense={true} divider={true}>
                        <ListItemIcon>
                          <SettingsApplications />
                        </ListItemIcon>
                        <ListItemText primary={platform} />
                      </ListItem>
                    ),
                  )}
                </List>
              </div>
              <AttackPatternSubAttackPatterns attackPattern={attackPattern} />
            </Grid>
            <Grid item={true} xs={6}>
              <StixCoreObjectKillChainPhasesView
                killChainPhasesEdges={attackPattern.killChainPhases.edges}
                firstLine={true}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Detection')}
              </Typography>
              <ExpandableMarkdown
                source={attackPattern.x_mitre_detection}
                limit={400}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Required permissions')}
              </Typography>
              <List>
                {propOr([], 'x_mitre_permissions_required', attackPattern).map(
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
              <AttackPatternCoursesOfAction attackPattern={attackPattern} />
              <AttackPatternDataComponents attackPattern={attackPattern} />
            </Grid>
          </Grid>
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
        description
        x_mitre_platforms
        x_mitre_permissions_required
        x_mitre_id
        x_mitre_detection
        isSubAttackPattern
        killChainPhases {
          edges {
            node {
              id
              entity_type
              kill_chain_name
              phase_name
              x_opencti_order
            }
          }
        }
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
        ...AttackPatternSubAttackPatterns_attackPattern
        ...AttackPatternParentAttackPatterns_attackPattern
        ...AttackPatternCoursesOfAction_attackPattern
        ...AttackPatternDataComponents_attackPattern
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(AttackPatternDetails);
