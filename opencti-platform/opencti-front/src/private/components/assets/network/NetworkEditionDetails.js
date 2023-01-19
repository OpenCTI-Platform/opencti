/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Field } from 'formik';
import { compose, split } from 'ramda';
import * as Yup from 'yup';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import SwitchField from '../../../../components/SwitchField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import Paper from '@material-ui/core/Paper';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { parse } from '../../../../utils/Time';
import TextField from '../../../../components/TextField';
import { adaptFieldValue } from '../../../../utils/String';
import TaskType from '../../common/form/TaskType';
import AddressField from '../../common/form/AddressField';
import HyperLinkField from '../../common/form/HyperLinkField';

const styles = () => ({
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
        # ...Network_network
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
    const { t, classes, enableReferences, network, setFieldValue } = this.props;
    return (
      <>
        <div style={{ height: '100%' }}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Details')}
          </Typography>
          <Paper classes={{ root: classes.paper }} elevation={2}>
            <Grid container={true} spacing={3}>
              <Grid container spacing={3}>
                <Grid item={true} xs={6}>
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
                </Grid>
                <Grid item={true} xs={6}>
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
                    containerstyle={{ width: '100%' }}
                  />
                </Grid>
              </Grid>
              <Grid container spacing={3}>
                <Grid item={true} xs={6}>
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
                </Grid>
                <Grid item={true} xs={6}>
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
                </Grid>
              </Grid>
              <Grid container spacing={3}>
                <Grid item={true} xs={6}>
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
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      name="is_scanned"
                      containerstyle={{ marginLeft: 10, marginRight: '-15px' }}
                      inputProps={{ 'aria-label': 'ant design' }}
                    />
                    <Typography>Yes</Typography>
                  </div>
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Last Scanned')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Last Scanned')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={DateTimePickerField}
                    variant="outlined"
                    name="last_scanned"
                    size="small"
                    invalidDateMessage={t(
                      'The value must be a date (YYYY-MM-DD HH:MM)',
                    )}
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '100%' }}
                  />
                </Grid>
              </Grid>
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 20 }}
                  >
                    {t('Implementation Point')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Implementation Point')}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <TaskType
                    name='implementation_point'
                    taskType='ImplementationPoint'
                    fullWidth={true}
                    variant='outlined'
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '100%' }}
                  />
                </Grid>
              </Grid>
              <Grid item={true} xs={12}>
                <HyperLinkField
                  variant='outlined'
                  type='hardware'
                  multiple={true}
                  name="connected_assets"
                  fullWidth={true}
                  style={{ height: '38.09px' }}
                  containerstyle={{ width: '90%' }}
                  helperText={'Indicates connected hardware on this entity.'}
                  data={network?.connected_assets}
                  title={'Connected Assets'}
                  setFieldValue={setFieldValue}
                  link='/defender HQ/assets/devices'
                />
              </Grid>
              <Grid item={true} xs={12}>
                <HyperLinkField
                  variant='outlined'
                  type='risks'
                  multiple={true}
                  name="related_risks"
                  fullWidth={true}
                  style={{ height: '38.09px' }}
                  containerstyle={{ width: '90%' }}
                  helperText={'Indicates the risks related to this entity.'}
                  data={network?.related_risks}
                  title={'Related Risks'}
                  setFieldValue={setFieldValue}
                  link='/activities/risk_assessment/risks'
                />
              </Grid>
            </Grid>
          </Paper>
        </div>
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
