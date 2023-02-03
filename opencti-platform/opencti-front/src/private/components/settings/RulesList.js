import React, { useEffect, useState } from 'react';
import * as R from 'ramda';
import { interval } from 'rxjs';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Switch from '@mui/material/Switch';
import { graphql, createRefetchContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import LinearProgress from '@mui/material/LinearProgress';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import Chart from 'react-apexcharts';
import { useTheme } from '@mui/styles';
import { ArrowRightAlt, SettingsSuggestOutlined } from '@mui/icons-material';
import { Database, GraphOutline, AutoFix } from 'mdi-material-ui';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import { FIVE_SECONDS, parse } from '../../../utils/Time';
import { useFormatter } from '../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../relay/environment';
import ItemBoolean from '../../../components/ItemBoolean';
import Transition from '../../../components/Transition';
import { areaChartOptions } from '../../../utils/Charts';
import { simpleNumberFormat } from '../../../utils/Number';
import ItemNumberDifference from '../../../components/ItemNumberDifference';

const interval$ = interval(FIVE_SECONDS);

const useStyles = makeStyles((theme) => ({
  card: {
    width: '100%',
    margin: '10px 0 10px 0',
    borderRadius: 6,
    position: 'relative',
  },
  number: {
    marginTop: 10,
    float: 'left',
    fontSize: 30,
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
    fontWeight: 500,
    color: theme.palette.text.secondary,
  },
  icon: {
    position: 'absolute',
    color: theme.palette.primary.main,
    top: 35,
    right: 20,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
  cardContent: {
    marginTop: -10,
    paddingTop: 0,
    height: 80,
    overflow: 'hidden',
    lineHeight: 2.5,
  },
  cardActions: {
    position: 'absolute',
    bottom: 0,
    width: '100%',
    padding: '0 10px 20px 10px',
  },
  progress: {
    width: '100%',
    borderRadius: 5,
    height: 10,
  },
  paper: {
    margin: '10px 0 0 0',
    padding: 0,
    overflow: 'hidden',
    height: '100%',
  },
  graphContainer: {
    width: '100%',
    padding: 0,
    overflow: 'hidden',
  },
  definition: {
    width: '100%',
    height: '100%',
    padding: '0 10px 0 10px',
    display: 'flex',
    alignItems: 'center',
  },
  left: {
    width: '100%',
  },
  middle: {
    textAlign: 'center',
    paddingLeft: 30,
    paddingRight: 30,
  },
  right: {
    width: '100%',
  },
  step: {
    margin: 10,
    minWidth: 400,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: 50,
  },
  if: {
    minWidth: 30,
    maxWidth: 30,
    height: 30,
    paddingTop: 3,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    border: `1px solid ${theme.palette.primary.main}`,
    textAlign: 'center',
    boxSizing: 'border-box',
  },
  action: {
    width: 80,
    height: 30,
    paddingTop: 3,
    marginRight: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    border: `1px solid ${theme.palette.secondary.main}`,
    textAlign: 'center',
    boxSizing: 'border-box',
  },
  element: {
    height: '100%',
    padding: 10,
    flexGrow: 1,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: theme.palette.background.nav,
  },
  source: {
    width: '30%',
    margin: '0 10px 0 10px',
    padding: 3,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    fontFamily: 'Consolas, monaco, monospace',
    textAlign: 'center',
  },
  relation: {
    flexGrow: 1,
    margin: '0 10px 0 10px',
    padding: 3,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'center',
  },
  target: {
    width: '30%',
    margin: '0 10px 0 10px',
    padding: 3,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'center',
  },
  then: {
    width: 80,
    height: 30,
    paddingTop: 3,
    margin: '0 auto',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'center',
    border: `1px solid ${theme.palette.primary.main}`,
  },
}));

export const rulesListRuleActivationMutation = graphql`
  mutation RulesListRuleActivationMutation($id: ID!, $enable: Boolean!) {
    ruleSetActivation(id: $id, enable: $enable) {
      id
      name
      description
      activated
    }
  }
`;

export const rulesListQuery = graphql`
  query RulesListQuery($startDate: DateTime!) {
    ...RulesList_rules
  }
`;

const RulesListComponent = ({ relay, data, keyword }) => {
  const classes = useStyles();
  const { t, nsdt, md, n } = useFormatter();
  const theme = useTheme();
  const [displayDisable, setDisplayDisable] = useState(false);
  const [displayEnable, setDisplayEnable] = useState(false);
  const [selectedRule, setSelectedRule] = useState(false);
  const [processing, setProcessing] = useState(false);
  useEffect(() => {
    const subscription = interval$.subscribe(() => relay.refetch());
    return () => {
      subscription.unsubscribe();
    };
  }, []);
  const handleOpenEnable = (rule) => {
    setDisplayEnable(true);
    setSelectedRule(rule);
  };
  const handleCloseEnable = () => {
    setDisplayEnable(false);
    setSelectedRule(null);
  };
  const handleOpenDisable = (rule) => {
    setDisplayDisable(true);
    setSelectedRule(rule);
  };
  const handleCloseDisable = () => {
    setDisplayDisable(false);
    setSelectedRule(null);
  };
  const submitEnableRule = () => {
    setProcessing(true);
    commitMutation({
      mutation: rulesListRuleActivationMutation,
      variables: {
        id: selectedRule,
        enable: true,
      },
      onCompleted: () => {
        setProcessing(false);
        MESSAGING$.notifySuccess(
          t('The rule has been enabled, rescan of platform data launched...'),
        );
        handleCloseEnable();
      },
    });
  };
  const submitDisableRule = () => {
    setProcessing(true);
    commitMutation({
      mutation: rulesListRuleActivationMutation,
      variables: {
        id: selectedRule,
        enable: false,
      },
      onCompleted: () => {
        setProcessing(false);
        MESSAGING$.notifySuccess(
          t('The rule has been disabled, clean-up launched...'),
        );
        handleCloseDisable();
      },
    });
  };
  const sortByNameCaseInsensitive = R.sortBy(
    R.compose(R.toLower, R.prop('name')),
  );
  const filterByKeyword = (p) => keyword === ''
    || p.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
    || p.description.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
    || p.category.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
  const rules = R.pipe(
    R.propOr([], 'rules'),
    R.filter(filterByKeyword),
    R.groupBy(R.prop('category')),
    R.toPairs,
    R.map((o) => [o[0], sortByNameCaseInsensitive(o[1])]),
    R.fromPairs,
  )(data);
  const categories = R.pipe(
    R.map((o) => ({ key: o, name: t(o) })),
    sortByNameCaseInsensitive,
  )(Object.keys(rules));
  const tasks = R.pathOr([], ['tasks', 'edges'], data);
  const modules = R.pathOr([], ['settings', 'platform_modules'], data);
  const isEngineEnabled = R.head(
    R.filter((p) => p.id === 'RULE_ENGINE', modules),
  )?.enable;
  const ruleManagerInfo = R.propOr({}, 'ruleManagerInfo', data);
  const chartDataEntities = data.stixDomainObjectsTimeSeries.map((entry) => {
    const date = new Date(entry.date);
    date.setDate(date.getDate() + 15);
    return {
      x: date,
      y: entry.value,
    };
  });
  const chartDataRelations = data.stixCoreRelationshipsTimeSeries.map(
    (entry) => {
      const date = new Date(entry.date);
      date.setDate(date.getDate() + 15);
      return {
        x: date,
        y: entry.value,
      };
    },
  );
  const totalRelations = data.stixCoreRelationshipsNumber.total;
  const differenceRelations = totalRelations - data.stixCoreRelationshipsNumber.count;
  const totalEntities = data.stixDomainObjectsNumber.total;
  const differenceEntities = totalEntities - data.stixDomainObjectsNumber.count;
  return (
    <div className={classes.container}>
      <Grid container={true} spacing={3}>
        <Grid item={true} xs={6}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Card
                classes={{ root: classes.card }}
                style={{ height: 110 }}
                variant="outlined"
              >
                <CardContent>
                  <div className={classes.title}>
                    {t('Total inferred entities')}
                  </div>
                  <div className={classes.number}>{n(totalEntities)}</div>
                  <ItemNumberDifference
                    difference={differenceEntities}
                    description={t('24 hours')}
                  />
                  <div className={classes.icon}>
                    <Database color="inherit" fontSize="large" />
                  </div>
                </CardContent>
              </Card>
            </Grid>
            <Grid item={true} xs={6}>
              <Card
                classes={{ root: classes.card }}
                style={{ height: 110 }}
                variant="outlined"
              >
                <CardContent>
                  <div className={classes.title}>
                    {t('Total inferred relations')}
                  </div>
                  <div className={classes.number}>{n(totalRelations)}</div>
                  <ItemNumberDifference
                    difference={differenceRelations}
                    description={t('24 hours')}
                  />
                  <div className={classes.icon}>
                    <GraphOutline color="inherit" fontSize="large" />
                  </div>
                </CardContent>
              </Card>
            </Grid>
            <Grid item={true} xs={6}>
              <Card
                classes={{ root: classes.card }}
                style={{ height: 110 }}
                variant="outlined"
              >
                <CardContent>
                  <div className={classes.title}>
                    {t('Rules engine status')}
                  </div>
                  <div style={{ marginTop: 20 }}>
                    <ItemBoolean
                      status={ruleManagerInfo.activated}
                      label={
                        ruleManagerInfo.activated ? t('Enabled') : t('Disabled')
                      }
                    />
                  </div>
                  <div className={classes.icon}>
                    <AutoFix color="inherit" fontSize="large" />
                  </div>
                </CardContent>
              </Card>
            </Grid>
            <Grid item={true} xs={6}>
              <Card
                classes={{ root: classes.card }}
                style={{ height: 110 }}
                variant="outlined"
              >
                <CardContent>
                  <div className={classes.title}>
                    {t('Last event processed')}
                  </div>
                  <div style={{ marginTop: 20 }}>
                    {nsdt(
                      parse(
                        parseInt(
                          (ruleManagerInfo.lastEventId || '-').split('-')[0],
                          10,
                        ),
                      ),
                    )}
                  </div>
                  <div className={classes.icon}>
                    <SettingsSuggestOutlined color="inherit" fontSize="large" />
                  </div>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Grid>
        <Grid item={true} xs={6}>
          <Paper
            variant="outlined"
            classes={{ root: classes.paper }}
            style={{ maxHeight: 262, minHeight: 262 }}
          >
            <div className={classes.graphContainer}>
              <Chart
                options={areaChartOptions(
                  theme,
                  true,
                  md,
                  simpleNumberFormat,
                  'dataPoints',
                )}
                series={[
                  {
                    name: t('Inferred entities'),
                    data: chartDataEntities,
                  },
                  {
                    name: t('Inferred relationships'),
                    data: chartDataRelations,
                  },
                ]}
                type="area"
                width="100%"
                height={240}
              />
            </div>
          </Paper>
        </Grid>
      </Grid>
      {categories.map((category) => {
        return (
          <div key={category.key} style={{ margin: '20px 0 50px 0' }}>
            <Typography
              variant="h2"
              gutterBottom={true}
              style={{ marginBottom: 20 }}
            >
              {category.name}
            </Typography>
            {rules[category.key].map((rule) => {
              const task = R.head(
                R.map(
                  (p) => p.node,
                  R.filter((p) => p.node.rule === rule.id, tasks),
                ),
              );
              const displayDefinition = rule.display;
              return (
                <Grid
                  key={rule.id}
                  container={true}
                  spacing={3}
                  style={{ marginBottom: 50 }}
                >
                  <Grid item={true} xs={3}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t(rule.name)}
                    </Typography>
                    <Paper
                      variant="outlined"
                      classes={{ root: classes.paper }}
                      style={{ padding: 15, minWidth: 280 }}
                    >
                      <Grid container={true} spacing={3}>
                        <Grid item={true} xs={6}>
                          <Typography variant="h3">
                            {t('Description')}
                          </Typography>
                          {t(rule.description)}
                        </Grid>
                        <Grid item={true} xs={6}>
                          <Typography variant="h3" gutterBottom={true}>
                            {t('Status')}
                          </Typography>
                          <FormGroup>
                            <FormControlLabel
                              control={
                                <Switch
                                  disabled={!isEngineEnabled}
                                  checked={isEngineEnabled && rule.activated}
                                  color="secondary"
                                  onChange={() => (rule.activated
                                    ? handleOpenDisable(rule.id)
                                    : handleOpenEnable(rule.id))
                                  }
                                />
                              }
                              label={
                                isEngineEnabled && rule.activated
                                  ? t('Enabled')
                                  : t('Disabled')
                              }
                            />
                          </FormGroup>
                        </Grid>
                        <Grid item={true} xs={12}>
                          {isEngineEnabled && task && (
                            <div
                              style={{
                                width: '100%',
                                textAlign: 'center',
                                fontSize: 9,
                                fontFamily: 'Consolas, monaco, monospace',
                              }}
                            >
                              {task.enable
                                ? t(
                                  task.completed
                                    ? 'This rule has been applied on the existing data'
                                    : 'Applying this rule on the existing data',
                                )
                                : t(
                                  task.completed
                                    ? 'Rule has been cleaned up on the existing data'
                                    : 'Cleaning up this rule on the existing data',
                                )}
                              <LinearProgress
                                classes={{ root: classes.progress }}
                                variant="determinate"
                                value={
                                  // eslint-disable-next-line no-nested-ternary
                                  task.task_expected_number === 0
                                    ? task.completed
                                      ? 100
                                      : 0
                                    : task.completed
                                      ? 100
                                      : Math.round(
                                        (task.task_processed_number
                                          / task.task_expected_number)
                                          * 100,
                                      )
                                }
                              />
                            </div>
                          )}
                        </Grid>
                      </Grid>
                    </Paper>
                  </Grid>
                  <Grid item={true} xs={9}>
                    <Paper
                      variant="outlined"
                      classes={{ root: classes.paper }}
                      style={{ marginTop: 25 }}
                    >
                      <div className={classes.definition}>
                        <div className={classes.left}>
                          {displayDefinition.if.map((step, index) => {
                            return (
                              <div key={index} className={classes.step}>
                                <div className={classes.if}>{t('IF')}</div>
                                <div className={classes.element}>
                                  <div
                                    className={classes.source}
                                    style={{
                                      border: `1px solid ${step.source_color}`,
                                    }}
                                  >
                                    {step.source}
                                  </div>
                                  <div
                                    className={classes.relation}
                                    style={{
                                      border: step.identifier_color
                                        ? `1px solid ${step.identifier_color}`
                                        : 'transparent',
                                    }}
                                  >
                                    {t(step.relation)}
                                  </div>
                                  <div
                                    className={classes.target}
                                    style={{
                                      border: `1px solid ${step.target_color}`,
                                    }}
                                  >
                                    {step.target}
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                        <div className={classes.middle}>
                          <ArrowRightAlt fontSize="large" />
                          <br />
                          <div className={classes.then}>{t('THEN')}</div>
                        </div>
                        <div className={classes.right}>
                          {displayDefinition.then.map((step, index) => {
                            return (
                              <div key={index} className={classes.step}>
                                <div className={classes.action}>
                                  {step.action}
                                </div>
                                <div className={classes.element}>
                                  <div
                                    className={classes.source}
                                    style={{
                                      border: `1px solid ${step.source_color}`,
                                    }}
                                  >
                                    {step.source}
                                  </div>
                                  {step.relation && (
                                    <div
                                      className={classes.relation}
                                      style={{
                                        border: step.identifier_color
                                          ? `1px solid ${step.identifier_color}`
                                          : 'transparent',
                                      }}
                                    >
                                      {t(step.relation)}
                                    </div>
                                  )}
                                  {step.target && (
                                    <div
                                      className={classes.target}
                                      style={{
                                        border: `1px solid ${step.target_color}`,
                                      }}
                                    >
                                      {step.target}
                                    </div>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </Paper>
                  </Grid>
                </Grid>
              );
            })}
          </div>
        );
      })}
      <Dialog
        open={displayEnable}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseEnable}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to enable this rule?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseEnable} disabled={processing}>
            {t('Cancel')}
          </Button>
          <Button
            onClick={submitEnableRule}
            color="secondary"
            disabled={processing}
          >
            {t('Enable')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayDisable}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDisable}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to disable this rule?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDisable} disabled={processing}>
            {t('Cancel')}
          </Button>
          <Button
            onClick={submitDisableRule}
            color="secondary"
            disabled={processing}
          >
            {t('Disable')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default createRefetchContainer(
  RulesListComponent,
  {
    data: graphql`
      fragment RulesList_rules on Query {
        settings {
          platform_modules {
            id
            enable
            running
          }
        }
        stixDomainObjectsTimeSeries(
          field: "created_at"
          types: ["Stix-Object"]
          operation: count
          startDate: $startDate
          interval: "month"
          onlyInferred: true
        ) {
          date
          value
        }
        stixCoreRelationshipsTimeSeries(
          field: "created_at"
          relationship_type: ["stix-relationship"]
          operation: count
          startDate: $startDate
          interval: "month"
          onlyInferred: true
        ) {
          date
          value
        }
        stixDomainObjectsNumber(types: ["Stix-Object"], onlyInferred: true) {
          total
          count
        }
        stixCoreRelationshipsNumber(relationship_type: ["stix-relationship"], onlyInferred: true) {
          total
          count
        }
        ruleManagerInfo {
          id
          activated
          lastEventId
          errors {
            timestamp
          }
        }
        rules {
          id
          name
          description
          activated
          display {
            if {
              action
              source
              source_color
              relation
              target
              target_color
              identifier
              identifier_color
            }
            then {
              action
              source
              source_color
              relation
              target
              target_color
              identifier
              identifier_color
            }
          }
          category
        }
        tasks(
          orderBy: created_at
          orderMode: desc
          filters: { key: type, values: ["RULE"] }
        ) {
          edges {
            node {
              id
              created_at
              task_expected_number
              task_processed_number
              completed
              ... on RuleTask {
                rule
                enable
              }
            }
          }
        }
      }
    `,
  },
  rulesListQuery,
);
