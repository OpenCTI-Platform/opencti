import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withRouter } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import { interval } from 'rxjs';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import CardActions from '@mui/material/CardActions';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import Switch from '@mui/material/Switch';
import { graphql, createRefetchContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@mui/material/Card';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import LinearProgress from '@mui/material/LinearProgress';
import Markdown from 'react-markdown';
import { AutoFix } from 'mdi-material-ui';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { FIVE_SECONDS, parse } from '../../../utils/Time';
import inject18n from '../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../relay/environment';
import { truncate } from '../../../utils/String';
import ItemBoolean from '../../../components/ItemBoolean';

const interval$ = interval(FIVE_SECONDS);

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: 200,
    borderRadius: 6,
    position: 'relative',
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
    margin: '10px 0 20px 0',
    padding: '15px',
    borderRadius: 6,
    position: 'relative',
  },
});

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

class RulesListComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDisable: false,
      displayEnable: false,
      selectedRule: null,
      processing: false,
    };
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleOpenEnable(rule) {
    this.setState({ displayEnable: true, selectedRule: rule });
  }

  handleCloseEnable() {
    this.setState({ displayEnable: false, selectedRule: null });
  }

  handleOpenDisable(rule) {
    this.setState({ displayDisable: true, selectedRule: rule });
  }

  handleCloseDisable() {
    this.setState({ displayDisable: false, selectedRule: null });
  }

  submitEnableRule() {
    this.setState({ processing: true });
    commitMutation({
      mutation: rulesListRuleActivationMutation,
      variables: {
        id: this.state.selectedRule,
        enable: true,
      },
      onCompleted: () => {
        this.setState({ processing: false });
        MESSAGING$.notifySuccess(
          this.props.t(
            'The rule has been enabled, rescan of platform data launched...',
          ),
        );
        this.handleCloseEnable();
      },
    });
  }

  submitDisableRule() {
    this.setState({ processing: true });
    commitMutation({
      mutation: rulesListRuleActivationMutation,
      variables: {
        id: this.state.selectedRule,
        enable: false,
      },
      onCompleted: () => {
        this.setState({ processing: false });
        MESSAGING$.notifySuccess(
          this.props.t('The rule has been disabled, clean-up launched...'),
        );
        this.handleCloseDisable();
      },
    });
  }

  render() {
    const { classes, t, data, keyword, nsdt } = this.props;
    const sortByNameCaseInsensitive = R.sortBy(
      R.compose(R.toLower, R.prop('name')),
    );
    const filterByKeyword = (p) => keyword === ''
      || p.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || p.description.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
    const rules = R.pipe(
      R.propOr([], 'rules'),
      R.filter(filterByKeyword),
      sortByNameCaseInsensitive,
    )(data);
    const tasks = R.pathOr([], ['tasks', 'edges'], data);
    const modules = R.pathOr([], ['settings', 'platform_modules'], data);
    const isEngineEnabled = R.head(
      R.filter((p) => p.id === 'RULE_ENGINE', modules),
    )?.enable;
    const ruleManagerInfo = R.propOr({}, 'ruleManagerInfo', data);
    return (
      <div>
        <div style={{ width: '100%' }}>
          <Paper
            variant="outlined"
            classes={{ root: classes.paper }}
            style={{ marginTop: 20 }}
          >
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={8}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Rule manager')}
                </Typography>
                <ItemBoolean
                  status={ruleManagerInfo.activated}
                  label={
                    ruleManagerInfo.activated ? t('Enabled') : t('Disabled')
                  }
                />
              </Grid>
              <Grid item={true} xs={4}>
                <div style={{ paddingLeft: 24 }}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Last processed')}
                  </Typography>
                  {nsdt(
                    parse(
                      parseInt(
                        (ruleManagerInfo.lastEventId || '-').split('-')[0],
                        10,
                      ),
                    ),
                  )}
                </div>
              </Grid>
            </Grid>
          </Paper>
        </div>
        <Grid container={true} spacing={3}>
          {rules.map((rule) => {
            const task = R.head(
              R.map(
                (p) => p.node,
                R.filter((p) => p.node.rule === rule.id, tasks),
              ),
            );
            return (
              <Grid key={rule.id} item={true} xs={4}>
                <Card
                  classes={{ root: classes.card }}
                  raised={false}
                  variant="outlined"
                >
                  <CardHeader
                    avatar={<AutoFix />}
                    action={
                      <Switch
                        disabled={!isEngineEnabled}
                        checked={isEngineEnabled && rule.activated}
                        color="secondary"
                        onChange={
                          rule.activated
                            ? this.handleOpenDisable.bind(this, rule.id)
                            : this.handleOpenEnable.bind(this, rule.id)
                        }
                      />
                    }
                    title={rule.name}
                    subheader={
                      task
                        ? t('Enabled the ') + nsdt(task.created_at)
                        : t('Never enabled')
                    }
                  />
                  <Tooltip
                    classes={{ tooltip: classes.tooltip }}
                    title={
                      <Markdown
                        remarkPlugins={[remarkGfm, remarkParse]}
                        parserOptions={{ commonmark: true }}
                        className="markdown"
                      >
                        {rule.description}
                      </Markdown>
                    }
                  >
                    <CardContent classes={{ root: classes.cardContent }}>
                      <Markdown
                        remarkPlugins={[remarkGfm, remarkParse]}
                        parserOptions={{ commonmark: true }}
                        className="markdown"
                      >
                        {truncate(rule.description, 180)}
                      </Markdown>
                    </CardContent>
                  </Tooltip>
                  <CardActions classes={{ root: classes.cardActions }}>
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
                  </CardActions>
                </Card>
              </Grid>
            );
          })}
        </Grid>
        <Dialog
          open={this.state.displayEnable}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseEnable.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to enable this rule?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseEnable.bind(this)}
              disabled={this.state.processing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitEnableRule.bind(this)}
              color="secondary"
              disabled={this.state.processing}
            >
              {t('Enable')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          open={this.state.displayDisable}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDisable.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to disable this rule?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseDisable.bind(this)}
              disabled={this.state.processing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitDisableRule.bind(this)}
              color="primary"
              disabled={this.state.processing}
            >
              {t('Disable')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

RulesListComponent.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
  nsdt: PropTypes.func,
  data: PropTypes.object,
};

export const rulesListQuery = graphql`
  query RulesListQuery {
    ...RulesList_rules
  }
`;

const RulesList = createRefetchContainer(
  RulesListComponent,
  {
    data: graphql`
      fragment RulesList_rules on Query {
        settings {
          platform_modules {
            id
            enable
          }
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

export default R.compose(inject18n, withRouter, withStyles(styles))(RulesList);
