import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import { interval } from 'rxjs';
import { Sync } from '@material-ui/icons';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import CardActions from '@material-ui/core/CardActions';
import IconButton from '@material-ui/core/IconButton';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import Avatar from '@material-ui/core/Avatar';
import Switch from '@material-ui/core/Switch';
import { createRefetchContainer } from 'react-relay';
import Grid from '@material-ui/core/Grid';
import Card from '@material-ui/core/Card';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import { FIVE_SECONDS } from '../../../utils/Time';
import inject18n from '../../../components/i18n';
import { commitMutation } from '../../../relay/environment';

const interval$ = interval(FIVE_SECONDS);

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: '100%',
    borderRadius: 6,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
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
      displayRescan: false,
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

  handleOpenRescan(rule) {
    this.setState({ displayRescan: true, selectedRule: rule });
  }

  handleCloseRescan() {
    this.setState({ displayRescan: false, selectedRule: null });
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
        this.handleCloseEnable();
      },
    });
  }

  render() {
    const {
      classes, t, data, keyword,
    } = this.props;
    const sortByNameCaseInsensitive = R.sortBy(
      R.compose(R.toLower, R.prop('name')),
    );
    const filterByKeyword = (n) => keyword === ''
      || n.user.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || n.user.description.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
    const rules = R.pipe(
      R.propOr([], 'rules'),
      R.filter(filterByKeyword),
      sortByNameCaseInsensitive,
    )(data);
    return (
      <div>
        <Grid container={true} spacing={3}>
          {rules.map((rule) => (
            <Grid key={rule.id} item={true} xs={4}>
              <Card
                classes={{ root: classes.card }}
                raised={false}
                variant="outlined"
              >
                <CardHeader
                  avatar={
                    <Avatar aria-label="recipe" className={classes.avatar}>
                      {rule.name.charAt(0)}
                    </Avatar>
                  }
                  action={
                    <Switch
                      checked={rule.activated}
                      color="primary"
                      onChange={
                        rule.activated
                          ? this.handleOpenDisable.bind(this, rule.id)
                          : this.handleOpenEnable.bind(this, rule.id)
                      }
                    />
                  }
                  title={rule.name}
                  subheader={rule.name}
                />
                <CardContent>{rule.description}</CardContent>
                <CardActions disableSpacing>
                  <IconButton>
                    <Sync />
                  </IconButton>
                </CardActions>
              </Card>
            </Grid>
          ))}
        </Grid>
        <Dialog
          open={this.state.displayEnable}
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
              color="primary"
              disabled={this.state.processing}
            >
              {t('Enable')}
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
        rules {
          id
          name
          description
          activated
        }
      }
    `,
  },
  rulesListQuery,
);

export default R.compose(inject18n, withRouter, withStyles(styles))(RulesList);
