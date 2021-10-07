import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import FormControl from '@material-ui/core/FormControl';
import FormGroup from '@material-ui/core/FormGroup';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Checkbox from '@material-ui/core/Checkbox';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import { Add, Close } from '@material-ui/icons';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import Chip from '@material-ui/core/Chip';
import Fab from '@material-ui/core/Fab';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import inject18n from '../../../components/i18n';
import { commitMutation } from '../../../relay/environment';
import Filters, { isUniqFilter } from '../common/lists/Filters';
import { truncate } from '../../../utils/String';
import StixDomainObjectsField from '../common/form/StixDomainObjectsField';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/SelectField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'absolute',
    bottom: 30,
    right: 30,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  filters: {
    marginTop: 20,
  },
  filter: {
    margin: '0 10px 10px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.chip,
    margin: '0 10px 10px 0',
  },
});

const userSubscriptionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  cron: Yup.string().required(t('This field is required')),
  entities_ids: Yup.array(),
});

const userSubscriptionMutation = graphql`
  mutation UserSubscriptionCreationMutation($input: UserSubscriptionAddInput!) {
    userSubscriptionAdd(input: $input) {
      id
      name
      cron
      options
      filters
      last_run
      entities {
        ... on BasicObject {
          id
          entity_type
          parent_types
        }
        ... on StixCoreObject {
          created_at
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            edges {
              node {
                id
                definition
              }
            }
          }
        }
        ... on StixDomainObject {
          created
        }
        ... on AttackPattern {
          name
          x_mitre_id
        }
        ... on Campaign {
          name
          first_seen
        }
        ... on CourseOfAction {
          name
        }
        ... on Note {
          attribute_abstract
          content
        }
        ... on ObservedData {
          first_observed
          last_observed
        }
        ... on Opinion {
          opinion
        }
        ... on Report {
          name
          published
        }
        ... on Individual {
          name
        }
        ... on Organization {
          name
        }
        ... on Sector {
          name
        }
        ... on System {
          name
        }
        ... on Indicator {
          name
          valid_from
        }
        ... on Infrastructure {
          name
        }
        ... on IntrusionSet {
          name
        }
        ... on Position {
          name
        }
        ... on City {
          name
        }
        ... on Country {
          name
        }
        ... on Region {
          name
        }
        ... on Malware {
          name
          first_seen
          last_seen
        }
        ... on ThreatActor {
          name
          first_seen
          last_seen
        }
        ... on Tool {
          name
        }
        ... on Vulnerability {
          name
        }
        ... on Incident {
          name
          first_seen
          last_seen
        }
      }
    }
  }
`;

class UserSubscriptionCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      options: ['KNOWLEDGE', 'CONTAINERS', 'TECHNICAL'],
      filters: {},
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({
      open: false,
      options: ['KNOWLEDGE', 'CONTAINERS', 'TECHNICAL'],
      filters: {},
    });
  }

  handleChangeOption(value) {
    const { options } = this.state;
    if (options.includes(value)) {
      this.setState({ options: R.filter((n) => n !== value, options) });
    } else {
      this.setState({ options: [...options, value] });
    }
  }

  handleNameChange(event) {
    this.setState({ name: event.target.value });
  }

  handleChangeCron(event) {
    this.setState({ cron: event.target.value });
  }

  handleAddFilter(key, id, value) {
    const { filters } = this.state;
    if (filters[key] && filters[key].length > 0) {
      this.setState({
        filters: R.assoc(
          key,
          isUniqFilter(key)
            ? [
              {
                id,
                value,
              },
            ]
            : R.uniqBy(R.prop('id'), [
              {
                id,
                value,
              },
              ...filters[key],
            ]),
          filters,
        ),
      });
    } else {
      this.setState({ filters: R.assoc(key, [{ id, value }], filters) });
    }
  }

  handleRemoveFilter(key) {
    const { filters } = this.state;
    this.setState({ filters: R.dissoc(key, filters) });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const adaptedValues = R.pipe(
      R.assoc('filters', JSON.stringify(this.state.filters)),
      R.assoc('options', this.state.options),
      R.assoc('entities_ids', R.pluck('value', values.entities_ids)),
    )(values);
    commitMutation({
      mutation: userSubscriptionMutation,
      variables: {
        input: adaptedValues,
      },
      updater: (store) => {
        const payload = store.getRootField('userSubscriptionAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node');
        const entity = store.get(this.props.userId);
        const conn = ConnectionHandler.getConnection(
          entity,
          'Pagination_userSubscriptions',
        );
        ConnectionHandler.insertEdgeBefore(conn, newEdge);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
    });
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const { t, classes, disabled } = this.props;
    const { filters, options } = this.state;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
          disabled={disabled}
        >
          <Add />
        </Fab>
        <Drawer
          open={this.state.open}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
            </IconButton>
            <Typography variant="h6">{t('Create a subscription')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                entities_ids: [],
                cron: '5-minutes',
              }}
              validationSchema={userSubscriptionValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onReset.bind(this)}
            >
              {({ submitForm, handleReset, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Field
                    component={SelectField}
                    name="cron"
                    label={t('Periodicity')}
                    fullWidth={true}
                    containerstyle={{ width: '100%', marginTop: 20 }}
                  >
                    <MenuItem value="5-minutes">{t('As it happens')}</MenuItem>
                    <MenuItem value="1-hours">{t('Every 1 hour')}</MenuItem>
                    <MenuItem value="24-hours">{t('Every 24 hours')}</MenuItem>
                    <MenuItem value="1-weeks">{t('Every week')}</MenuItem>
                  </Field>
                  <FormControl component="fieldset" style={{ marginTop: 20 }}>
                    <FormGroup>
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={options.includes('KNOWLEDGE')}
                            onChange={this.handleChangeOption.bind(
                              this,
                              'KNOWLEDGE',
                            )}
                            name="KNOWLEDGE"
                          />
                        }
                        label={t(
                          'Knowledge update (except indicators & observables)',
                        )}
                      />
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={options.includes('CONTAINERS')}
                            onChange={this.handleChangeOption.bind(
                              this,
                              'CONTAINERS',
                            )}
                            name="CONTAINERS"
                          />
                        }
                        label={t('Containers (reports, notes & opinions)')}
                      />
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={options.includes('TECHNICAL')}
                            onChange={this.handleChangeOption.bind(
                              this,
                              'TECHNICAL',
                            )}
                            name="TECHNICAL"
                          />
                        }
                        label={t(
                          'Technical elements (indicators & observables)',
                        )}
                      />
                    </FormGroup>
                  </FormControl>
                  <StixDomainObjectsField
                    name="entities_ids"
                    types={[
                      'Threat-Actor',
                      'Intrusion-Set',
                      'Campaign',
                      'Incident',
                      'Malware',
                      'Vulnerability',
                      'Tool',
                    ]}
                    multiple={true}
                    fullWidth={true}
                    style={{ width: '100%', marginTop: 20 }}
                    helpertext={t(
                      'Optional, you may want to subscribe to specific entities.',
                    )}
                  />
                  <div style={{ marginTop: 20 }}>
                    <Filters
                      variant="text"
                      availableFilterKeys={[
                        'markedBy',
                        'labelledBy',
                        'createdBy',
                        'confidence_gt',
                      ]}
                      currentFilters={[]}
                      handleAddFilter={this.handleAddFilter.bind(this)}
                      noDirectFilters={true}
                    />
                  </div>
                  <div className="clearfix" />
                  <div className={classes.filters}>
                    {R.map((currentFilter) => {
                      const label = `${truncate(
                        t(`filter_${currentFilter[0]}`),
                        20,
                      )}`;
                      const values = (
                        <span>
                          {R.map(
                            (n) => (
                              <span key={n.value}>
                                {n.value && n.value.length > 0
                                  ? truncate(n.value, 15)
                                  : t('No label')}{' '}
                                {R.last(currentFilter[1]).value !== n.value && (
                                  <code>OR</code>
                                )}{' '}
                              </span>
                            ),
                            currentFilter[1],
                          )}
                        </span>
                      );
                      return (
                        <span key={currentFilter[0]}>
                          <Chip
                            classes={{ root: classes.filter }}
                            label={
                              <div>
                                <strong>{label}</strong>: {values}
                              </div>
                            }
                            onDelete={this.handleRemoveFilter.bind(
                              this,
                              currentFilter[0],
                            )}
                          />
                          {R.last(R.toPairs(filters))[0]
                            !== currentFilter[0] && (
                            <Chip
                              classes={{ root: classes.operator }}
                              label={t('AND')}
                            />
                          )}
                        </span>
                      );
                    }, R.toPairs(filters))}
                  </div>
                  <div className="clearfix" />
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      onClick={handleReset}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      variant="contained"
                      color="primary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Create')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </div>
        </Drawer>
      </div>
    );
  }
}

UserSubscriptionCreation.propTypes = {
  userId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  disabled: PropTypes.bool,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(UserSubscriptionCreation);
