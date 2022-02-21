import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import * as Yup from 'yup';
import * as R from 'ramda';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Switch from '@material-ui/core/Switch';
import Paper from '@material-ui/core/Paper';
import MenuItem from '@material-ui/core/MenuItem';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import { Information } from 'mdi-material-ui';
import AddIcon from '@material-ui/icons/Add';
import Tooltip from '@material-ui/core/Tooltip';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import OpenVocabField from '../../common/form/OpenVocabField';
import { dateFormat, parse } from '../../../../utils/Time';
import DatePickerField from '../../../../components/DatePickerField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
});

const riskMutationFieldPatch = graphql`
  mutation RiskEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    editRisk(id: $id, input: $input) {
      id
    }
  }
`;

const riskEditionDetailsFocus = graphql`
  mutation RiskEditionDetailsFocusMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    editRisk(id: $id, input: $input) {
      id
    }
  }
`;

class RiskEditionDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: riskEditionDetailsFocus,
      variables: {
        id: this.props.risk?.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  render() {
    const {
      t, classes, risk, context, enableReferences,
    } = this.props;
    const relatedRisksEdges = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.map((value) => ({
        name: value.node.name,
        description: value.node.description,
        statement: value.node.statement,
        risk_status: value.node.risk_status,
        deadline: value.node.deadline,
        false_positive: value.node.false_positive,
        risk_adjusted: value.node.risk_adjusted,
        vendor_dependency: value.node.vendor_dependency,
        impacted_control_id: value.node.impacted_control_id,
      })),
      R.mergeAll,
    )(risk);
    const relatedObservationsEdges = R.pipe(
      R.pathOr([], ['related_observations', 'edges']),
      R.map((value) => ({
        impacted_component: value.node.impacted_component,
        impacted_asset: value.node.subjects,
      })),
    )(risk);
    const riskDetectionSource = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.mergeAll,
      R.pathOr([], ['node', 'characterizations']),
      R.mergeAll,
      R.path(['origins']),
      R.mergeAll,
      R.path(['origin_actors']),
      R.mergeAll,
    )(risk);
    const initialValues = R.pipe(
      R.assoc('id', risk?.id || ''),
      R.assoc('created', risk?.created || ''),
      R.assoc('modified', risk?.modified || ''),
      R.assoc('description', relatedRisksEdges?.description || ''),
      R.assoc('responsible_parties', risk?.responsible_parties || ''),
      R.assoc('labels', risk?.labels || []),
      R.assoc('name', relatedRisksEdges?.name || ''),
      R.assoc('statement', relatedRisksEdges?.statement || ''),
      R.assoc('risk_status', relatedRisksEdges?.risk_status || ''),
      R.assoc('deadline', dateFormat(relatedRisksEdges?.deadline)),
      R.assoc('detection_source', riskDetectionSource?.detection_source || ''),
      R.assoc('impacted_control', risk?.impacted_control || ''),
      R.assoc('false_positive', relatedRisksEdges?.false_positive || ''),
      R.assoc('operationally_required', relatedRisksEdges?.risk_adjusted || ''),
      R.assoc('risk_adjusted', relatedRisksEdges?.risk_adjusted || ''),
      R.assoc('vendor_dependency', relatedRisksEdges?.vendor_dependency || ''),
      R.pick([
        'id',
        'created',
        'modified',
        'description',
        'responsible_parties',
        'labels',
        'name',
        'statement',
        'risk_status',
        'deadline',
        'detection_source',
        'impacted_control',
        'false_positive',
        'operationally_required',
        'risk_adjusted',
        'vendor_dependency',
      ]),
    )(risk);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
      >
      <div>
        <div style={{ height: '100%' }}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Details')}
          </Typography>
          <Paper classes={{ root: classes.paper }} elevation={2}>
            <Grid item={true} xs={12} style={{ marginBottom: '21px' }}>
              <Grid item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Name')}
                </Typography>
                <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="name"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
              <Grid container={true} spacing={3} style={{ marginBottom: '9px' }}>
                  <Grid item={true} xs={6}>
                    <Grid item={true}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Created')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip
                          title={t(
                            'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={DatePickerField}
                        variant='outlined'
                        size='small'
                        name="created"
                        fullWidth={true}
                        invalidDateMessage={t(
                          'The value must be a date (YYYY-MM-DD)',
                        )}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Grid item={true}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Last Modified')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip
                          title={t(
                            'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={DatePickerField}
                        variant='outlined'
                        size='small'
                        name="modified"
                        fullWidth={true}
                        invalidDateMessage={t(
                          'The value must be a date (YYYY-MM-DD)',
                        )}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                </Grid>
              <Grid container={true} spacing={3}>
                <Grid xs={12} item={true}>
                  <Grid style={{ marginBottom: '15px' }} item={true}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left' }}
                    >
                      {t('Description')}
                    </Typography>
                    <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                      <Tooltip
                        title={t(
                          'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                        )}
                      >
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    <Field
                      component={TextField}
                      name="description"
                      fullWidth={true}
                      multiline={true}
                      rows="3"
                      variant='outlined'
                    />
                  </Grid>
                </Grid>
              </Grid>
              <Grid container={true} spacing={3}>
                <Grid xs={12} item={true}>
                  <Grid style={{ marginBottom: '15px' }} item={true}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left' }}
                    >
                      {t('Statement')}
                    </Typography>
                    <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                      <Tooltip
                        title={t(
                          'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                        )}
                      >
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    <Field
                      component={TextField}
                      name="statement"
                      fullWidth={true}
                      multiline={true}
                      rows="3"
                      variant='outlined'
                    />
                  </Grid>
                </Grid>
              </Grid>
            <Grid container={true} spacing={3}>
              <Grid xs={6} item={true}>
                <Grid style={{ marginBottom: '15px' }} item={true}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Risk Status')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title={t(
                        'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                      )}
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <AddIcon fontSize="small" style={{ margin: '-3px 0 0 0' }} />
                  <div className="clearfix" />
                  <Field
                    component={SelectField}
                    variant='outlined'
                    name="risk_status"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                  />
                </Grid>
                <Grid style={{ marginBottom: '15px' }} item={true}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Detection Source')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title={t(
                        'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                      )}
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    variant='outlined'
                    size='small'
                    name="detection_source"
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  />
                </Grid>
                <Grid style={{ marginBottom: '15px' }} item={true}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('False-Positive')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title={t(
                        'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                      )}
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={SelectField}
                    variant='outlined'
                    name="false_positive"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                  />
                </Grid>
                <Grid style={{ marginBottom: '15px' }} item={true}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Risk Adjusted')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title={t(
                        'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                      )}
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={SelectField}
                    variant='outlined'
                    name="risk_adjusted"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                  />
                </Grid>
              </Grid>
              <Grid item={true} xs={6}>
                <Grid style={{ marginBottom: '20px' }} item={true}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Deadline')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title={t(
                        'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                      )}
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={DatePickerField}
                    variant='outlined'
                    size='small'
                    name="deadline"
                    fullWidth={true}
                    invalidDateMessage={t(
                      'The value must be a date (YYYY-MM-DD)',
                    )}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '100%' }}
                  />
                </Grid>
                <Grid style={{ marginBottom: '15px' }} item={true}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Impacted Control')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title={t(
                        'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                      )}
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    variant='outlined'
                    size='small'
                    name="impacted_control"
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  />
                </Grid>
                <Grid style={{ marginBottom: '15px' }} item={true}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Operationally Required')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title={t(
                        'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                      )}
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={SelectField}
                    variant='outlined'
                    name="operationally_required"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                  />
                </Grid>
                <Grid style={{ marginBottom: '15px' }} item={true}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Vendor Dependency')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title={t(
                        'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                      )}
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={SelectField}
                    variant='outlined'
                    name="vendor_dependency"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                  />
                </Grid>
              </Grid>
            </Grid>
          </Paper>
        </div>
        {/* <Grid item={true} xs={6}>
            <div style={{ display: 'grid', gridTemplateColumns: '50% 50%', marginTop: '20px' }}>
            <div style={{ marginRight: '20px' }}>
              <Form>
                <Grid style={{ marginBottom: '80px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Installed Operating System')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Installed Operating System')} >
                      <Information fontSize="small" color="primary" />
 <Information fontSize="inherit"color="disabled" />                     </Tooltip>
                    <AddIcon fontSize="small" color="primary" />
                  </div>
                  <Field
                    component={TextField}
                    variant= 'outlined'
                    name="installed_operating_system"
                    label={t('Installed Operating System')}
                    size= 'small'
                    fullWidth={true}
                    helperText={
                      <SubscriptionFocus
                      context={context}
                      fieldName="installed_operating_system"
                      />
                    }
                  />
                </Grid>
                <Grid style={{ marginBottom: '15px' }}>
                </Grid>
                <Grid style={{ marginBottom: '15px' }}>
                </Grid>
                  <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                  <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
              </Form>
            </div>
            <div>
            <Form>
            <Grid style={{ marginBottom: '15px' }}>
            </Grid>
                      <Grid style={{ marginBottom: '15px' }}>
                    </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                      <Grid style={{ marginBottom: '15px' }}>
                    </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
              </Form>
            </div>
            </div> */}
        {/* <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={riskValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
        >
          {({ submitForm, isSubmitting, validateForm }) => (
            <div>
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={DatePickerField}
                  name="first_seen"
                  label={t('First seen')}
                  invalidDateMessage={t(
                    'The value must be a date (YYYY-MM-DD)',
                  )}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={context}
                      fieldName="first_seen"
                    />
                  }
                />
                <Field
                  component={DatePickerField}
                  name="last_seen"
                  label={t('Last seen')}
                  invalidDateMessage={t(
                    'The value must be a date (YYYY-MM-DD)',
                  )}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={context}
                      fieldName="last_seen"
                    />
                  }
                />
                <Field
                  component={SelectField}
                  style={{ height: '38.09px' }}
                  name="sophistication"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Sophistication')}
                  fullWidth={true}
                  containerstyle={{ width: '100%', marginTop: 20 }}
                  helpertext={
                    <SubscriptionFocus
                      context={context}
                      fieldName="sophistication"
                    />
                  }
                >
                  <MenuItem key="none" value="none">
                    {t('sophistication_none')}
                  </MenuItem>
                  <MenuItem key="minimal" value="minimal">
                    {t('sophistication_minimal')}
                  </MenuItem>
                  <MenuItem key="intermediate" value="intermediate">
                    {t('sophistication_intermediate')}
                  </MenuItem>
                  <MenuItem key="advanced" value="advanced">
                    {t('sophistication_advanced')}
                  </MenuItem>
                  <MenuItem key="expert" value="expert">
                    {t('sophistication_expert')}
                  </MenuItem>
                  <MenuItem key="innovator" value="innovator">
                    {t('sophistication_innovator')}
                  </MenuItem>
                  <MenuItem key="strategic" value="strategic">
                    {t('sophistication_strategic')}
                  </MenuItem>
                </Field>
                <OpenVocabField
                  label={t('Resource level')}
                  type="attack-resource-level-ov"
                  name="resource_level"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                  variant="edit"
                  multiple={false}
                  editContext={context}
                />
                <OpenVocabField
                  label={t('Primary motivation')}
                  type="attack-motivation-ov"
                  name="primary_motivation"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                  variant="edit"
                  multiple={false}
                  editContext={context}
                />
                <OpenVocabField
                  label={t('Secondary motivations')}
                  type="attack-motivation-ov"
                  name="secondary_motivations"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                  variant="edit"
                  multiple={true}
                  editContext={context}
                />
                <OpenVocabField
                  label={t('Personal motivations')}
                  type="attack-motivation-ov"
                  name="personal_motivations"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                  variant="edit"
                  multiple={true}
                  editContext={context}
                />
                <Field
                  component={TextField}
                  name="goals"
                  label={t('Goals (1 / line)')}
                  fullWidth={true}
                  multiline={true}
                  rows="3"
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus context={context} fieldName="goals" />
                  }
                />
                {enableReferences && (
                  <CommitMessage
                    submitForm={submitForm}
                    disabled={isSubmitting}
                    validateForm={validateForm}
                  />
                )}
              </Form>
            </div>
          )}
        </Formik> */}
      </div>
      </Formik>
    );
  }
}

RiskEditionDetailsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  risk: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

// const RiskEditionDetails = createFragmentContainer(
//   RiskEditionDetailsComponent,
//   {
//     risk: graphql`
//       fragment RiskEditionDetails_risk on ThreatActor {
//         id
//         first_seen
//         last_seen
//         sophistication
//         resource_level
//         primary_motivation
//         secondary_motivations
//         personal_motivations
//         goals
//       }
//     `,
//   },
// );

const RiskEditionDetails = createFragmentContainer(
  RiskEditionDetailsComponent,
  {
    risk: graphql`
      fragment RiskEditionDetails_risk on POAMItem {
        id
        created
        modified
        poam_id     # Item ID
        name        # Weakness
        description
        labels {
          id
          name
          color
          description
        }
        origins {
          id
          origin_actors {       # only use if UI support Detection Source
            actor_type
            actor {
              ... on Component {
                id
                name
              }
              ... on OscalParty {
                id
                name
              }
            }
          }
        }
        links {
          id
          created
          modified
          external_id     # external id
          source_name     # Title
          description     # description
          url             # URL
          media_type      # Media Type
        }
        remarks {
          id
          abstract
          content
          authors
        }
        related_risks {
          edges {
            node{
              id
              created
              modified
              name
              description
              statement
              risk_status       # Risk Status
              deadline
              priority
              impacted_control_id
              accepted
              false_positive    # False-Positive
              risk_adjusted     # Operational Required
              vendor_dependency # Vendor Dependency
              characterizations {
                origins {
                  id
                  origin_actors {
                    actor_type
                    actor {
                      ... on Component {
                        id
                        component_type
                        name          # Detection Source
                      }
                      ... on OscalParty {
                      id
                      party_type
                      name            # Detection Source
                      }
                    }
                  }
                }
              }
              remediations {
                response_type
                lifecycle
              }
            }
          }
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RiskEditionDetails);
