import React, { FunctionComponent, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
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
import Box from '@mui/material/Box';
import DecayDialogContent from './DecayDialogContent';
import DecayExclusionDialogContent from './DecayExclusionDialogContent';
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
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import { Stack } from '@mui/material';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
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
      <Card title={t_i18n('Details')}>
        <Label>
          {t_i18n('Indicator pattern')}
        </Label>
        <ExpandablePre source={indicator.pattern ?? ''} limit={300} />
        <Grid container={true} spacing={2} sx={{ mt: 0 }}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Valid from')}
            </Label>
            <Chip
              classes={{ root: classes.chip }}
              label={fldt(indicator.valid_from)}
            />
            <Label
              sx={{ mt: 2 }}
              action={indicator.decay_applied_rule && (
                <Tooltip
                  title={t_i18n(
                    'This score is updated with the decay rule applied to this indicator.',
                  )}
                >
                  <InformationOutline fontSize="small" color="primary" />
                </Tooltip>
              )}
            >
              {t_i18n('Score')}
            </Label>
            <Stack direction="row">
              <ItemScore score={indicator.x_opencti_score} />
              {(indicator.decay_applied_rule
                || !!indicator.decay_exclusion_applied_rule) && (
                <>
                  <Button
                    size="small"
                    variant="secondary"
                    onClick={openLifecycleDialog}
                    startIcon={<TroubleshootOutlined />}
                    color={indicator.decay_exclusion_applied_rule ? 'warning' : undefined}
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
                </>
              )}
            </Stack>
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown
              source={indicator.description}
              limit={400}
              removeLinks
            />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Valid until')}
            </Label>
            <Chip
              classes={{ root: classes.chip }}
              label={fldt(indicator.valid_until)}
            />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Detection')}
            </Label>
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
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Indicator types')}
            </Label>
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
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Main observable type')}
            </Label>
            <FieldOrEmpty source={indicator.x_opencti_main_observable_type}>
              <Chip
                classes={{ root: classes.chip }}
                label={indicator.x_opencti_main_observable_type}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Platforms')}
            </Label>
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
      </Card>
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
      x_opencti_reliability
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
