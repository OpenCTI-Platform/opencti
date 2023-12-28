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
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DecayDialogContent from '@components/observations/indicators/DecayDialog';
import DialogActions from '@mui/material/DialogActions';
import DialogTitle from '@mui/material/DialogTitle';
import ItemScore from '../../../../components/ItemScore';
import IndicatorObservables from './IndicatorObservables';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ExpandablePre from '../../../../components/ExpandablePre';
import ItemBoolean from '../../../../components/ItemBoolean';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import Transition from '../../../../components/Transition';

const useStyles = makeStyles<Theme>((theme) => ({
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
    color: theme.palette.primary.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
}));

interface IndicatorDetailsComponentProps {
  indicator: IndicatorDetails_indicator$data,
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
    <div style={{ height: '100%' }} className="break">
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Indicator pattern')}
        </Typography>
        <ExpandablePre source={indicator.pattern ?? ''} limit={300} />
        <Grid
          container={true}
          spacing={3}
          style={{ marginTop: 10, marginBottom: 10 }}
        >
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Valid from')}
            </Typography>
            <Chip classes={{ root: classes.chip }}
              label={fldt(indicator.valid_from)}
            />
            <Grid container columnSpacing={1} style={{ marginTop: 20 }}>
              <Grid item xs={4}>

                <Typography variant="h3" gutterBottom={true}>
                  <div style = {{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <div>{t_i18n('Score')}</div>
                    {indicator.x_opencti_decay_rule && (
                      <Tooltip title={t_i18n('This score is updated with the decay rule applied to this indicator.')}>
                        <InformationOutline fontSize="small" color="primary" />
                      </Tooltip>
                    )}
                  </div>
                </Typography>
                <ItemScore score={indicator.x_opencti_score} />
              </Grid>
              {indicator.x_opencti_decay_rule && (
              <Grid item xs={8}>
                <Button
                  size="small"
                  variant="outlined"
                  onClick={openLifecycleDialog}
                  startIcon={<TroubleshootOutlined />}
                  style={{ marginTop: 22 }}
                >
                  {t_i18n('Lifecycle')}
                </Button>
                <Dialog
                  PaperProps={{ elevation: 1 }}
                  open={isLifecycleOpen}
                  keepMounted={true}
                  TransitionComponent={Transition}
                  onClose={onDecayLifecycleClose}
                  fullWidth
                  maxWidth="md"
                >
                  <DialogTitle>{t_i18n('Lifecycle details')}</DialogTitle>
                  <DecayDialogContent indicator={indicator} />
                  <DialogActions>
                    <Button onClick={onDecayLifecycleClose}>
                      {t_i18n('Close')}
                    </Button>
                  </DialogActions>
                </Dialog>
              </Grid>
              )}
            </Grid>
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown source={indicator.description} limit={400} />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Indicator types')}
            </Typography>
            {indicator.indicator_types && indicator.indicator_types.map((indicatorType) => (
              <Chip
                key={indicatorType}
                classes={{ root: classes.chip }}
                label={indicatorType}
              />
            ))}
          </Grid>
          <Grid item={true} xs={6}>
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
              style={{ marginTop: 20 }}
            >
              {t_i18n('Detection')}
            </Typography>
            <ItemBoolean
              label={indicator.x_opencti_detection ? t_i18n('Yes') : t_i18n('No')}
              status={indicator.x_opencti_detection}
            />
            <StixCoreObjectKillChainPhasesView killChainPhasesEdges={indicator.killChainPhases?.edges ?? []} />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Platforms')}
            </Typography>
            <List>
              { (indicator.x_mitre_platforms ?? []).map((platform) => (
                platform
                && <ListItem key={platform} dense={true} divider={true}>
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
      x_opencti_base_score
      x_opencti_detection
      x_mitre_platforms
      indicator_types
      x_opencti_decay_history {
        score
        updated_at
      }
      x_opencti_decay_rule {
        decay_lifetime
        decay_pound
        decay_points
        decay_revoke_score
        indicator_types
      }
      decayLiveDetails {
        live_score
        live_points {
          score
          updated_at
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
      ...IndicatorObservables_indicator
    }
  `,
});

export default IndicatorDetails;
