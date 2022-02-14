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
    console.log('riskEditionDetails', risk);
    return (
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
        poam_id                   #Item Id
        name                      #Weakness
        description
        labels {
          id
          name
          color
          description
        }
        related_risks {
          edges {
            node {
              id
              name
              description
              statement
              risk_status         #Risk Status
              deadline
              priority
              accepted
              false_positive      #False Positive
              risk_adjusted       #Operational Required
              vendor_dependency   #Vendor Dependency
              characterizations {
                id
                origins {
                  id
                  origin_actors {
                    actor_type
                    actor {
                      ... on OscalPerson {
                        id
                        name      #Detection Source
                      }
                    }
                  }
                }
              }
            }
          }
        }
        related_observations {
          edges {
            node {
              id
              name                #Impacted Component
              subjects {
                subject {
                  ... on HardwareComponent {
                    id
                    name          #Impacted Asset
                  }
                }
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
