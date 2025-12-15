import React, { FunctionComponent, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { SettingsApplications, TroubleshootOutlined } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import Chip from '@mui/material/Chip';
import Divider from '@mui/material/Divider';
import makeStyles from '@mui/styles/makeStyles';
import { IndicatorDetails_indicator$data } from '@components/observations/indicators/__generated__/IndicatorDetails_indicator.graphql';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DecayDialogContent from './DecayDialogContent';
import DecayExclusionDialogContent from './DecayExclusionDialogContent';

import Box from '@mui/material/Box';
import ItemScore from '../../../../components/ItemScore';
import IndicatorObservables from './IndicatorObservables';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ExpandablePre from '../../../../components/ExpandablePre';
import ItemBoolean from '../../../../components/ItemBoolean';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import Transition from '../../../../components/Transition';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    borderRadius: 4,
    color: theme.palette.primary.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
}));

interface IndicatorDetailsComponentProps {
  indicator: IndicatorDetails_indicator$data;
}

const IndicatorDetailsComponent: FunctionComponent<IndicatorDetailsComponentProps> = ({
  indicator,
}) => {
  const { t_i18n, fldt } = useFormatter();
  const [isLifecycleOpen, setIsLifecycleOpen] = useState(false);
  const classes = useStyles();
  const onDecayLifecycleClose = () => {
    setIsLifecycleOpen(false);
  };

  const openLifecycleDialog = () => {
    setIsLifecycleOpen(true);
  };

  return (
    <Box sx={{ height: '100%' }} className="break">
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper
        classes={{ root: classes.paper }}
        className="paper-for-grid"
        variant="outlined"
      >
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Indicator pattern')}
        </Typography>
        <ExpandablePre source={indicator.pattern ?? ''} limit={300} />
        <Grid container={true} spacing={3} sx={{ marginTop: '10px' }}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Valid from')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={fldt(indicator.valid_from)}
            />
            <Grid container columnSpacing={1} sx={{ marginTop: '20px' }}>
              <Grid item xs={4}>
                <Typography variant="h3" gutterBottom={true}>
                  <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                    <span>{t_i18n('Score')}</span>
                    {indicator.decay_applied_rule && (
                      <Tooltip
                        title={t_i18n(
                          'This score is updated with the decay rule applied to this indicator.',
                        )}
                      >
                        <InformationOutline fontSize="small" color="primary" />
                      </Tooltip>
                    )}
                  </Box>
                </Typography>
                <ItemScore score={indicator.x_opencti_score} />
              </Grid>
              {(indicator.decay_applied_rule
                || !!indicator.decay_exclusion_applied_rule) && (
                <Grid item xs={8}>
                  <Button
                    size="small"
                    variant="secondary"
                    onClick={openLifecycleDialog}
                    startIcon={<TroubleshootOutlined />}
                    sx={{ marginTop: '22px' }}
                    color={indicator.decay_exclusion_applied_rule ? 'warning' : 'primary'}
                  >
                    {t_i18n('Lifecycle')}
                  </Button>
                  <Dialog
                    slotProps={{ paper: { elevation: 1 } }}
                    open={isLifecycleOpen}
                    keepMounted={true}
                    slots={{ transition: Transition }}
                    onClose={onDecayLifecycleClose}
                    fullWidth
                    maxWidth="lg"
                  >
                    {indicator.decay_exclusion_applied_rule ? (
                      <DecayExclusionDialogContent
                        indicator={indicator}
                        onClose={onDecayLifecycleClose}
                      />
                    ) : (
                      <DecayDialogContent
                        indicator={indicator}
                        onClose={onDecayLifecycleClose}
                      />
                    )}
                  </Dialog>
                </Grid>
              )}
            </Grid>
            <Typography
              variant="h3"
              gutterBottom={true}
              sx={{ marginTop: '20px' }}
            >
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown
              source={indicator.description}
              limit={400}
              removeLinks
            />
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Valid until')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={fldt(indicator.valid_until)}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              sx={{ marginTop: '20px' }}
            >
              {t_i18n('Detection')}
            </Typography>
            <ItemBoolean
              label={
                indicator.x_opencti_detection ? t_i18n('Yes') : t_i18n('No')
              }
              status={indicator.x_opencti_detection}
            />
            <StixCoreObjectKillChainPhasesView
              killChainPhases={indicator.killChainPhases ?? []}
            />
          </Grid>
        </Grid>
        <Grid container={true} spacing={3} sx={{ marginBottom: '10px' }}>
          <Grid item xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
              sx={{ marginTop: '20px' }}
            >
              {t_i18n('Indicator types')}
            </Typography>
            <FieldOrEmpty source={indicator.indicator_types}>
              {indicator.indicator_types?.map((indicatorType) => (
                <Chip
                  key={indicatorType}
                  classes={{ root: classes.chip }}
                  label={indicatorType}
                />
              ))}
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
              sx={{ marginTop: '20px' }}
            >
              {t_i18n('Main observable type')}
            </Typography>
            <FieldOrEmpty source={indicator.x_opencti_main_observable_type}>
              <Chip
                classes={{ root: classes.chip }}
                label={indicator.x_opencti_main_observable_type}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <Typography
              variant="h3"
              gutterBottom={true}
              sx={{ marginTop: '20px' }}
            >
              {t_i18n('Platforms')}
            </Typography>
            <FieldOrEmpty source={indicator.x_mitre_platforms}>
              <List>
                {indicator.x_mitre_platforms?.map(
                  (platform) =>
                    platform && (
                      <ListItem key={platform} dense={true} divider={true}>
                        <ListItemIcon>
                          <SettingsApplications />
                        </ListItemIcon>
                        <ListItemText primary={platform} />
                      </ListItem>
                    ),
                )}
              </List>
            </FieldOrEmpty>
          </Grid>
        </Grid>
        <Divider />
        <IndicatorObservables indicator={indicator} />
      </Paper>
    </Box>
  );
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
      x_opencti_main_observable_type
      x_mitre_platforms
      indicator_types
      decay_base_score
      decay_base_score_date
      decay_history {
        score
        updated_at
      }
      decay_exclusion_applied_rule {
        decay_exclusion_name
      }
      decay_applied_rule {
        decay_rule_id
        decay_lifetime
        decay_pound
        decay_points
        decay_revoke_score
      }
      decayLiveDetails {
        live_score
        live_points {
          score
          updated_at
        }
      }
      decayChartData {
        live_score_serie {
          updated_at
          score
        }
      }
      objectLabel {
        id
        value
        color
      }
      killChainPhases {
        id
        entity_type
        kill_chain_name
        phase_name
        x_opencti_order
      }
      ...IndicatorObservables_indicator
    }
  `,
});

export default IndicatorDetails;
