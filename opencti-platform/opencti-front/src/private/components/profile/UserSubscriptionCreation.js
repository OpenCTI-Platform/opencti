import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import FormControl from '@mui/material/FormControl';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { Add, Close } from '@mui/icons-material';
import MenuItem from '@mui/material/MenuItem';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import Chip from '@mui/material/Chip';
import Fab from '@mui/material/Fab';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
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
    backgroundColor: theme.palette.background.nav,
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
    backgroundColor: theme.palette.background.accent,
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
        ... on Event {
          name
          description
          start_time
          stop_time
        }
        ... on Channel {
          name
          description
        }
        ... on Narrative {
          name
          description
        }
        ... on Language {
          name
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
      options: ['ENTITIES', 'KNOWLEDGE', 'CONTAINERS', 'TECHNICAL'],
      filters: {},
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({
      open: false,
      options: ['ENTITIES', 'KNOWLEDGE', 'CONTAINERS', 'TECHNICAL'],
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
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
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
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="cron"
                    label={t('Periodicity')}
                    fullWidth={true}
                    containerstyle={{ width: '100%', marginTop: 20 }}
                  >
                    <MenuItem value="5-minutes">{t('As it happens')}</MenuItem>
                    <MenuItem value="1-hours">{t('Every 1 hour')}</MenuItem>
                    <MenuItem value="24-hours">{t('Every 24 hours')}</MenuItem>
                    <MenuItem value="1-weeks">{t('Every week')}</MenuItem>
                    <MenuItem value="1-months">{t('Every month')}</MenuItem>
                  </Field>
                  <FormControl component="fieldset" style={{ marginTop: 20 }}>
                    <FormGroup>
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={options.includes('ENTITIES')}
                            onChange={this.handleChangeOption.bind(
                              this,
                              'ENTITIES',
                            )}
                            name="ENTITIES"
                          />
                        }
                        label={
                          <div>
                            <div style={{ float: 'left' }}>
                              {t('Knowledge creations (entities)')}
                            </div>
                            <div
                              style={{ float: 'left', margin: '1px 0 0 8px' }}
                            >
                              <Tooltip
                                title={t(
                                  'Receive a digest of all created entities (you may filter with one or more entity types to avoid having too many results).',
                                )}
                              >
                                <InformationOutline
                                  fontSize="small"
                                  color="primary"
                                />
                              </Tooltip>
                            </div>
                          </div>
                        }
                      />
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
                        label={
                          <div>
                            <div style={{ float: 'left' }}>
                              {t('Knowledge updates (relations)')}
                            </div>
                            <div
                              style={{ float: 'left', margin: '1px 0 0 8px' }}
                            >
                              <Tooltip
                                title={t(
                                  'Receive a digest of all created relationships (except when related to indicators or observables).',
                                )}
                              >
                                <InformationOutline
                                  fontSize="small"
                                  color="primary"
                                />
                              </Tooltip>
                            </div>
                          </div>
                        }
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
                        label={
                          <div>
                            <div style={{ float: 'left' }}>
                              {t('Containers (reports, notes & opinions)')}
                            </div>
                            <div
                              style={{
                                float: 'left',
                                margin: '1px 0 0 8px',
                              }}
                            >
                              <Tooltip
                                title={t(
                                  'Receive a digest of all created containers (reports, notes and opinions).',
                                )}
                              >
                                <InformationOutline
                                  fontSize="small"
                                  color="primary"
                                />
                              </Tooltip>
                            </div>
                          </div>
                        }
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
                        label={
                          <div>
                            <div style={{ float: 'left' }}>
                              {t(
                                'Technical elements (indicators & observables)',
                              )}
                            </div>
                            <div
                              style={{ float: 'left', margin: '1px 0 0 8px' }}
                            >
                              <Tooltip
                                title={t(
                                  'Receive a digest of all created relationships to indicators and observables.',
                                )}
                              >
                                <InformationOutline
                                  fontSize="small"
                                  color="primary"
                                />
                              </Tooltip>
                            </div>
                          </div>
                        }
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
                      'Sector',
                      'Region',
                      'Country',
                      'City',
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
                        'entity_type',
                        'markedBy',
                        'labelledBy',
                        'createdBy',
                        'confidence_gt',
                      ]}
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
                      color="secondary"
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
