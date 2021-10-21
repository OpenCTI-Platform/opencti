import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import {
  assoc, compose, join, pick, pipe, split,
} from 'ramda';
import * as Yup from 'yup';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Switch from '@material-ui/core/Switch';
import Paper from '@material-ui/core/Paper';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import inject18n from '../../../../components/i18n';
import DatePickerField from '../../../../components/DatePickerField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import { dateFormat, parse } from '../../../../utils/Time';
import OpenVocabField from '../../common/form/OpenVocabField';
import TextField from '../../../../components/TextField';
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
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
});

const networkMutationFieldPatch = graphql`
  mutation NetworkEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
  ) {
    intrusionSetEdit(id: $id) {
      fieldPatch(input: $input, commitMessage: $commitMessage) {
        ...NetworkEditionDetails_network
        ...Network_network
      }
    }
  }
`;

const networkEditionDetailsFocus = graphql`
  mutation NetworkEditionDetailsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    intrusionSetEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const networkValidation = (t) => Yup.object().shape({
  first_observed: Yup.date()
    .nullable()
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  last_observed: Yup.date()
    .nullable()
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  resource_level: Yup.string().nullable(),
  primary_motivation: Yup.string().nullable(),
  secondary_motivations: Yup.array().nullable(),
  goals: Yup.string().nullable(),
});

class NetworkEditionDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: networkEditionDetailsFocus,
      variables: {
        id: this.props.network.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  onSubmit(values, { setSubmitting }) {
    const commitMessage = values.message;
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.assoc(
        'first_seen',
        values.first_seen ? parse(values.first_seen).format() : null,
      ),
      R.assoc(
        'last_seen',
        values.last_seen ? parse(values.last_seen).format() : null,
      ),
      R.assoc(
        'goals',
        values.goals && values.goals.length ? R.split('\n', values.goals) : [],
      ),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: networkMutationFieldPatch,
      variables: {
        id: this.props.network.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
      },
      onCompleted: () => {
        setSubmitting(false);
        this.props.handleClose();
      },
    });
  }

  handleSubmitField(name, value) {
    if (!this.props.enableReferences) {
      let finalValue = value;
      if (name === 'goals') {
        finalValue = split('\n', value);
      }
      networkValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: networkMutationFieldPatch,
            variables: {
              id: this.props.network.id,
              input: { key: name, value: finalValue || '' },
            },
          });
        })
        .catch(() => false);
    }
  }

  render() {
    const {
      t, classes, network, context, enableReferences,
    } = this.props;
    // const initialValues = pipe(
    //   assoc('first_seen', dateFormat(network.first_seen)),
    //   assoc('last_seen', dateFormat(network.last_seen)),
    //   assoc(
    //     'secondary_motivations',
    //     network.secondary_motivations
    //       ? network.secondary_motivations
    //       : [],
    //   ),
    //   assoc('goals', join('\n', network.goals ? network.goals : [])),
    //   pick([
    //     'first_seen',
    //     'last_seen',
    //     'resource_level',
    //     'primary_motivation',
    //     'secondary_motivations',
    //     'goals',
    //   ]),
    // )(network);
    return (
      <>
        {/* // <Formik
      //   enableReinitialize={true}
      //   initialValues={initialValues}
      //   validationSchema={networkValidation(t)}
      //   onSubmit={this.onSubmit.bind(this)}
      // >
      //   {({ submitForm, isSubmitting, validateForm }) => (
      //     <Form style={{ margin: '20px 0 20px 0' }}> */}
        <div style={{ height: '100%' }}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Details')}
          </Typography>
          <Paper classes={{ root: classes.paper }} elevation={2}>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={6}>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Network Name')}
                  </Typography>
                  <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                    <Tooltip title={t('Network Name')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="network_name"
                    size='small'
                    fullWidth={true}
                  />
                </div>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Starting Address')}
                  </Typography>
                  <div style={{ float: 'left', margin: '20px 0 0 5px' }}>
                    <Tooltip title={t('Starting Address')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    style={{ height: '38.09px' }}
                    variant='outlined'
                    name="starting_address"
                    size='small'
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  />
                </div>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Scanned')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Scanned')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Typography>No</Typography>
                    <Switch defaultChecked inputProps={{ 'aria-label': 'ant design' }} />
                    <Typography>Yes</Typography>
                  </div>
                </div>
              </Grid>
              <Grid item={true} xs={6}>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Network ID')}
                  </Typography>
                  <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                    <Tooltip title={t('Network ID')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    style={{ height: '38.09px' }}
                    variant='outlined'
                    name="network_id"
                    size='small'
                    fullWidth={true}
                    containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                  />
                </div>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Ending Address')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Ending Address')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="ending_address"
                    size='small'
                    fullWidth={true}
                  />
                </div>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Implementation Point')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Implementation Point')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="model"
                    size='small'
                    fullWidth={true}
                  />
                </div>
              </Grid>
            </Grid>
          </Paper>
        </div>
        {/* <Field
              component={DatePickerField}
              name="first_seen"
              label={t('First seen')}
              invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              // helperText={
              //   <SubscriptionFocus context={context} fieldName="first_seen" />
              // }
            />
            <Field
              component={DatePickerField}
              name="last_seen"
              label={t('Last seen')}
              invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
              fullWidth={true}
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              // helperText={
              //   <SubscriptionFocus context={context} fieldName="last_seen" />
              // }
            />
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
            <Field
              component={TextField}
              name="goals"
              label={t('Goals (1 / line)')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              // helperText={
              //   <SubscriptionFocus context={context} fieldName="goals" />
              // }
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                validateForm={validateForm}
              />
            )} */}
        {/* </Form>
        )}
      </Formik> */}
      </>
    );
  }
}

NetworkEditionDetailsComponent.propTypes = {
  t: PropTypes.func,
  network: PropTypes.object,
  context: PropTypes.array,
};

const NetworkEditionDetails = createFragmentContainer(
  NetworkEditionDetailsComponent,
  {
    network: graphql`
      fragment NetworkEditionDetails_network on IntrusionSet {
        id
        first_seen
        last_seen
        resource_level
        primary_motivation
        secondary_motivations
        goals
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(NetworkEditionDetails);
