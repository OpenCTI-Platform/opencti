import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import { Launch, SettingsApplications } from '@material-ui/icons';
import ListItemText from '@material-ui/core/ListItemText';
import Chip from '@material-ui/core/Chip';
import inject18n from '../../../../components/i18n';
import ItemScore from '../../../../components/ItemScore';
import IndicatorObservables from './IndicatorObservables';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ExpandablePre from '../../../../components/ExpandablePre';
import ItemBoolean from '../../../../components/ItemBoolean';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: 'rgba(0, 150, 136, 0.3)',
    color: '#ffffff',
    textTransform: 'uppercase',
    borderRadius: '0',
    margin: '0 5px 5px 0',
  },
});

class IndicatorDetailsComponent extends Component {
  render() {
    const {
      t, fld, classes, indicator,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Indicator pattern')}
          </Typography>
          <ExpandablePre source={indicator.pattern} limit={300} />
          <Grid container={true} spacing={3} style={{ marginTop: 10 }}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Valid from')}
              </Typography>
              <Chip
                classes={{ root: classes.chip }}
                label={fld(indicator.valid_from)}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Score')}
              </Typography>
              <ItemScore score={indicator.x_opencti_score} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Description')}
              </Typography>
              <ExpandableMarkdown source={indicator.description} limit={400} />
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Valid until')}
              </Typography>
              <Chip
                classes={{ root: classes.chip }}
                label={fld(indicator.valid_until)}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Detection')}
              </Typography>
              <ItemBoolean
                label={indicator.x_opencti_detection ? t('Yes') : t('No')}
                status={indicator.x_opencti_detection}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Kill chain phases')}
              </Typography>
              {indicator.killChainPhases.edges.length > 0 && (
                <List>
                  {indicator.killChainPhases.edges.map((killChainPhaseEdge) => {
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
              )}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Platforms')}
              </Typography>
              <List>
                {propOr([], 'x_mitre_platforms', indicator).map((platform) => (
                  <ListItem key={platform} dense={true} divider={true}>
                    <ListItemIcon>
                      <SettingsApplications />
                    </ListItemIcon>
                    <ListItemText primary={platform} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
          <IndicatorObservables indicator={indicator} />
        </Paper>
      </div>
    );
  }
}

IndicatorDetailsComponent.propTypes = {
  indicator: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const IndicatorDetails = createFragmentContainer(IndicatorDetailsComponent, {
  indicator: graphql`
    fragment IndicatorDetails_indicator on Indicator {
      id
      description
      pattern
      valid_from
      valid_until
      x_opencti_score
      x_opencti_detection
      x_mitre_platforms
      creator {
        id
        name
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
      killChainPhases {
        edges {
          node {
            id
            kill_chain_name
            phase_name
            x_opencti_order
          }
        }
      }
      ...IndicatorObservables_indicator
    }
  `,
});

export default compose(inject18n, withStyles(styles))(IndicatorDetails);
