import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { Launch, SettingsApplications } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import Chip from '@mui/material/Chip';
import Divider from '@mui/material/Divider';
import inject18n from '../../../../components/i18n';
import ItemScore from '../../../../components/ItemScore';
import IndicatorObservables from './IndicatorObservables';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ExpandablePre from '../../../../components/ExpandablePre';
import ItemBoolean from '../../../../components/ItemBoolean';

const styles = (theme) => ({
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
    backgroundColor: theme.palette.background.accent,
    borderRadius: 5,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
});

class IndicatorDetailsComponent extends Component {
  render() {
    const { t, fldt, classes, indicator } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Typography variant="h3" gutterBottom={true}>
            {t('Indicator pattern')}
          </Typography>
          <ExpandablePre source={indicator.pattern} limit={300} />
          <Grid
            container={true}
            spacing={3}
            style={{ marginTop: 10, marginBottom: 10 }}
          >
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Valid from')}
              </Typography>
              <Chip
                classes={{ root: classes.chip }}
                label={fldt(indicator.valid_from)}
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
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Indicator types')}
              </Typography>
              {indicator.indicator_types
                && indicator.indicator_types.map((indicatorType) => (
                  <Chip
                    key={indicatorType}
                    classes={{ root: classes.chip }}
                    label={indicatorType}
                  />
                ))}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Valid until')}
              </Typography>
              <Chip
                classes={{ root: classes.chip }}
                label={fldt(indicator.valid_until)}
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
          <Divider />
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
      indicator_types
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
