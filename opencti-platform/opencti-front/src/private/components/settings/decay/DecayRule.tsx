import React from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import DecayChart, { DecayHistory } from '@components/settings/decay/DecayChart';
import { useParams } from 'react-router-dom';
import { DecayRuleQuery } from '@components/settings/decay/__generated__/DecayRuleQuery.graphql';
import { Icon } from '@mui/material';
import DecayRuleEdition from './DecayRuleEdition';
import DecayRulePopover from './DecayRulePopover';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import CustomizationMenu from '../CustomizationMenu';
import { DecayRule_decayRule$key } from './__generated__/DecayRule_decayRule.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  paperFlex: {
    flex: 1,
    margin: '6px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  title: {
    float: 'left',
  },
}));

const decayRuleQuery = graphql`
  query DecayRuleQuery($id: String!) {
    decayRule(id: $id) {
      ...DecayRule_decayRule
    }
  }
`;

const decayRuleFragment = graphql`
  fragment DecayRule_decayRule on DecayRule {
    id
    name
    description
    built_in
    appliedIndicatorsCount
    created_at
    updated_at
    decay_lifetime
    decay_pound
    decay_points
    decay_revoke_score
    decay_observable_types
    active
    order
    decaySettingsChartData {
      live_score_serie {
        updated_at
        score
      }
    }
  }
`;

interface DecayRuleComponentProps {
  queryRef: PreloadedQuery<DecayRuleQuery>
}

const DecayRuleComponent = ({ queryRef }: DecayRuleComponentProps) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const queryResult = usePreloadedQuery(decayRuleQuery, queryRef);
  const decayRule = useFragment<DecayRule_decayRule$key>(decayRuleFragment, queryResult.decayRule);

  if (!decayRule) return null;

  let chartCurvePoints: DecayHistory[] = [];
  if (decayRule.decaySettingsChartData?.live_score_serie) {
    chartCurvePoints = decayRule.decaySettingsChartData.live_score_serie.map((historyPoint) => historyPoint);
  }

  let chartDecayReactionPoints: number[] = [];
  if (decayRule.decay_points) {
    chartDecayReactionPoints = decayRule.decay_points.map((point) => point);
  }

  return (
    <div className={classes.container}>
      <CustomizationMenu />
      {!decayRule.built_in && (
        <DecayRuleEdition decayRule={decayRule} />
      )}
      <div style={{ marginBottom: 23 }}>
        <Typography variant="h1" gutterBottom={true} classes={{ root: classes.title }}>
          {decayRule.name}
        </Typography>
        <ItemBoolean
          status={decayRule.active ?? false}
          label={decayRule.active ? t_i18n('Active') : t_i18n('Inactive')}
        />
        {!decayRule.built_in && (
          <div className={classes.popover}>
            <DecayRulePopover decayRule={decayRule} />
          </div>
        )}
        {decayRule.built_in && (
          <div className={classes.popover}>
            <Icon />
          </div>
        )}
      </div>
      <div className="clearfix" />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <Box sx={{ display: 'flex', height: '100%', flexDirection: 'column' }}>
            <Typography variant="h4" gutterBottom={true}>
              {t_i18n('Configuration')}
            </Typography>
            <Paper classes={{ root: classes.paperFlex }} variant="outlined">
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Description')}
                  </Typography>
                  <ExpandableMarkdown source={decayRule.description} limit={300} />
                </Grid>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Indicator observable types')}
                  </Typography>
                  <FieldOrEmpty source={decayRule.decay_observable_types}>
                    <span>{decayRule.decay_observable_types?.join(', ')}</span>
                  </FieldOrEmpty>
                </Grid>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Lifetime (in days)')}
                  </Typography>
                  {decayRule.decay_lifetime}
                </Grid>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Decay factor')}
                  </Typography>
                  {decayRule.decay_pound}
                </Grid>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Reaction points')}
                  </Typography>
                  <FieldOrEmpty source={decayRule.decay_points}>
                    <span>{decayRule.decay_points?.join(', ')}</span>
                  </FieldOrEmpty>
                </Grid>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Revoke score')}
                  </Typography>
                  {decayRule.decay_revoke_score}
                </Grid>
              </Grid>
            </Paper>
          </Box>
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Impact')}
          </Typography>
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {decayRule.appliedIndicatorsCount} {t_i18n('indicators currently impacted by this rule')}
          </Paper>
          <Typography variant="h4" gutterBottom={true} style={{ marginTop: 10 }}>
            {t_i18n('Life curve')}
          </Typography>
          <Paper classes={{ root: classes.paper }} variant="outlined">
            <DecayChart
              decayCurvePoint={chartCurvePoints}
              revokeScore={decayRule.decay_revoke_score}
              reactionPoints={chartDecayReactionPoints}
            />
          </Paper>
        </Grid>
      </Grid>
    </div>
  );
};

const DecayRule = () => {
  const { decayRuleId } = useParams();
  if (!decayRuleId) return null;

  const queryRef = useQueryLoading<DecayRuleQuery>(
    decayRuleQuery,
    { id: decayRuleId },
  );

  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <DecayRuleComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.container} />
  );
};

export default DecayRule;
