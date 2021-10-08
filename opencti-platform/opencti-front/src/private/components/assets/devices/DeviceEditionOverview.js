import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import * as Yup from 'yup';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Cancel from '@material-ui/icons/Cancel';
import Button from '@material-ui/core/Button';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StixCoreObjectLabelsView from '../../common/stix_core_objects/StixCoreObjectLabelsView';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '30px 30px 30px 30px',
  },
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

const deviceMutationFieldPatch = graphql`
  mutation DeviceEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
  ) {
    threatActorEdit(id: $id) {
      fieldPatch(input: $input, commitMessage: $commitMessage) {
        ...DeviceEditionOverview_device
        ...Device_device
      }
    }
  }
`;

export const deviceEditionOverviewFocus = graphql`
  mutation DeviceEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const deviceMutationRelationAdd = graphql`
  mutation DeviceEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    threatActorEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...DeviceEditionOverview_device
        }
      }
    }
  }
`;

const deviceMutationRelationDelete = graphql`
  mutation DeviceEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    threatActorEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...DeviceEditionOverview_device
      }
    }
  }
`;

const deviceValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  threat_actor_types: Yup.array(),
  confidence: Yup.number().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class DeviceEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: deviceEditionOverviewFocus,
      variables: {
        id: this.props.device.id,
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
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: deviceMutationFieldPatch,
      variables: {
        id: this.props.device.id,
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
      deviceValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: deviceMutationFieldPatch,
            variables: {
              id: this.props.device.id,
              input: { key: name, value: value || '' },
            },
          });
        })
        .catch(() => false);
    }
  }

  handleChangeCreatedBy(name, value) {
    if (!this.props.enableReferences) {
      commitMutation({
        mutation: deviceMutationFieldPatch,
        variables: {
          id: this.props.device.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    if (!this.props.enableReferences) {
      const { device } = this.props;
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(device);

      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);

      if (added.length > 0) {
        commitMutation({
          mutation: deviceMutationRelationAdd,
          variables: {
            id: this.props.device.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }

      if (removed.length > 0) {
        commitMutation({
          mutation: deviceMutationRelationDelete,
          variables: {
            id: this.props.device.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  }

  render() {
    const {
      t, classes, device, context, enableReferences,
    } = this.props;
    const createdBy = R.pathOr(null, ['createdBy', 'name'], device) === null
      ? ''
      : {
        label: R.pathOr(null, ['createdBy', 'name'], device),
        value: R.pathOr(null, ['createdBy', 'id'], device),
      };
    const killChainPhases = R.pipe(
      R.pathOr([], ['killChainPhases', 'edges']),
      R.map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
      })),
    )(device);
    const objectMarking = R.pipe(
      R.pathOr([], ['objectMarking', 'edges']),
      R.map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(device);
    const initialValues = R.pipe(
      R.assoc('createdBy', createdBy),
      R.assoc('killChainPhases', killChainPhases),
      R.assoc('objectMarking', objectMarking),
      R.assoc(
        'threat_actor_types',
        device.threat_actor_types ? device.threat_actor_types : [],
      ),
      R.pick([
        'name',
        'threat_actor_types',
        'confidence',
        'description',
        'createdBy',
        'killChainPhases',
        'objectMarking',
      ]),
    )(device);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={deviceValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
      >
        {({
          submitForm, isSubmitting, validateForm, setFieldValue,
        }) => (
          <>
          <div style={{ height: '100%' }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Basic Information')}
              </Typography>
              <Paper classes={{ root: classes.paper }} elevation={2}>
              <Form>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={6}>
                  <div>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('ID')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Installed Operating System')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <Field
                        component={TextField}
                        variant= 'outlined'
                        size= 'small'
                        name="id"
                        fullWidth={true}
                        containerstyle={{ width: '100%' }}
                        onFocus={this.handleChangeFocus.bind(this)}
                        onSubmit={this.handleSubmitField.bind(this)}
                        helperText={
                          <SubscriptionFocus context={context} fieldName="name" />
                        }
                      />
                    </div>
                    <div>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left', marginTop: 17 }}
                      >
                        {t('Asset ID')}
                      </Typography>
                      <div style={{ float: 'left', margin: '17px 0 0 5px' }}>
                        <Tooltip title={t('Installed Software')} >
                          <Information fontSize="inherit"color="disabled" />
                        </Tooltip>
                      </div>
                      <Field
                        component={TextField}
                        variant= 'outlined'
                        size= 'small'
                        name="assetId"
                        fullWidth={true}
                        containerstyle={{ width: '100%' }}
                        onFocus={this.handleChangeFocus.bind(this)}
                        onSubmit={this.handleSubmitField.bind(this)}
                        helperText={
                          <SubscriptionFocus context={context} fieldName="name" />
                        }
                      />
                    </div>
                    <div>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left', marginTop: 15 }}
                      >
                        {t('Description')}
                      </Typography>
                      <div style={{ float: 'left', margin: '16px 0 0 5px' }}>
                        <Tooltip
                          title={t(
                            'Description',
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                        <div className='scroll-bg'>
                            <div className='scroll-div'>
                              <div className='scroll-object'>
                              {[1, 2, 3, 4].map((data, key) => (
                                <>
                                  {t('Lorem Ipsum Lorem Ipsum')}
                                  <br></br>
                                </>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                      <div style={{ marginTop: '6px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 15 }}
                        >
                          {t('Version')}
                        </Typography>
                        <div style={{ float: 'left', margin: '16px 0 0 5px' }}>
                          <Tooltip
                            title={t(
                              'Version',
                            )}
                          >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          size= 'small'
                          name="version"
                          fullWidth={true}
                          containerstyle={{ width: '100%' }}
                          helperText={
                            <SubscriptionFocus context={context} fieldName="name" />
                          }
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 16 }}
                        >
                          {t('Serial Number')}
                        </Typography>
                        <div style={{ float: 'left', margin: '18px 0 0 5px' }}>
                          <Tooltip
                            title={t(
                              'Serial Number',
                            )}
                          >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          size= 'small'
                          name="serialNumber"
                          fullWidth={true}
                          containerstyle={{ width: '100%' }}
                          helperText={
                            <SubscriptionFocus context={context} fieldName="name" />
                          }
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 16 }}
                        >
                          {t('Responsible Parties')}
                        </Typography>
                        <div style={{ float: 'left', margin: '17px 0 0 5px' }}>
                          <Tooltip
                            title={t(
                              'Responsible Parties',
                            )}
                          >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                      <div className="clearfix" />
                      <Field
                          component={SelectField}
                          variant= 'outlined'
                          name="ports"
                          size= 'small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                          helperText={
                            <SubscriptionFocus
                            context={context}
                            fieldName="ports"
                            />
                          }
                        />
                        <Field
                          component={SelectField}
                          variant= 'outlined'
                          name="ports"
                          size= 'small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                          helperText={
                            <SubscriptionFocus
                            context={context}
                            fieldName="ports"
                            />
                          }
                        />
                        <Field
                          component={SelectField}
                          variant= 'outlined'
                          name="ports"
                          size= 'small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                          helperText={
                            <SubscriptionFocus
                            context={context}
                            fieldName="ports"
                            />
                          }
                        />
                        <Field
                          component={SelectField}
                          variant= 'outlined'
                          name="ports"
                          size= 'small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                          helperText={
                            <SubscriptionFocus
                            context={context}
                            fieldName="ports"
                            />
                          }
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Label')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip
                            title={t(
                              'Label',
                            )}
                          >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        {/* <StixCoreObjectLabelsView
                          labels={'stixDomainObject.objectLabel'}
                          marginTop={20}
                        /> */}
                                  {
                                    [1, 2, 3].map(() => (
                                        <>
                                           <Button size="small" variant="outlined" style={{ borderRadius: '25px', marginRight: '10px', padding: '1px 3px 1px 10px' }} color="disabled">Label <Cancel fontSize="small" style={{ marginLeft: '10px' }} /></Button>
                                        </>
                                    ))
                                  }
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
                      {t('Asset Type')}
                    </Typography>
                    <div style={{ float: 'left', margin: '2px 0 0 5px' }}>
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
                      variant= 'outlined'
                      name="assetType"
                      size= 'small'
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '100%' }}
                      helperText={
                        <SubscriptionFocus
                        context={context}
                        fieldName="AssetType"
                        />
                      }
                    />
                  </div>
                  <div>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left', marginTop: 20 }}
                    >
                      {t('Asset Tag')}
                    </Typography>
                    <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
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
                      variant= 'outlined'
                      name="assetTag"
                      size= 'small'
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '100%' }}
                      helperText={
                        <SubscriptionFocus
                        context={context}
                        fieldName="AssetType"
                        />
                      }
                    />
                  </div>
                  <div>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left', marginTop: 20 }}
                    >
                      {t('Location')}
                    </Typography>
                    <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                      <Tooltip
                        title={t(
                          'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                        )}
                      >
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    <div className='scroll-bg'>
                        <div className='scroll-div'>
                          <div className='scroll-object'>
                          {[1, 2, 3, 4].map((data, key) => (
                            <>
                              {t('Lorem Ipsum Lorem Ipsum')}
                              <br></br>
                            </>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left', marginTop: 20 }}
                    >
                      {t('Vendor Name')}
                    </Typography>
                    <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
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
                      variant= 'outlined'
                      name="vendorName"
                      size= 'small'
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '100%' }}
                      helperText={
                        <SubscriptionFocus
                        context={context}
                        fieldName="vendorName"
                        />
                      }
                    />
                  </div>
                  <div>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left', marginTop: 20 }}
                    >
                      {t('Release Date')}
                    </Typography>
                    <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
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
                      variant= 'outlined'
                      name="releaseDate"
                      size= 'small'
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '100%' }}
                      helperText={
                        <SubscriptionFocus
                        context={context}
                        fieldName="ReleaseDate"
                        />
                      }
                    />
                  </div>
                  <div>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left', marginTop: 20 }}
                    >
                      {t('Operation State')}
                    </Typography>
                    <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
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
                      variant= 'outlined'
                      name="operationState"
                      size= 'small'
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '100%' }}
                      helperText={
                        <SubscriptionFocus
                        context={context}
                        fieldName="OperationState"
                        />
                      }
                    />
                  </div>
                  </Grid>
                </Grid>
              </Form>
            </Paper>
          </div>
          {/* <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <Field
              component={SelectField}
              name="threat_actor_types"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Device types')}
              fullWidth={true}
              multiple={true}
              containerstyle={{ width: '100%', marginTop: 20 }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="threat_actor_types"
                />
              }
            >
              <MenuItem key="activist" value="activist">
                {t('activist')}
              </MenuItem>
              <MenuItem key="competitor" value="competitor">
                {t('competitor')}
              </MenuItem>
              <MenuItem key="crime-syndicate" value="crime-syndicate">
                {t('crime-syndicate')}
              </MenuItem>
              <MenuItem key="criminal'" value="criminal'">
                {t('criminal')}
              </MenuItem>
              <MenuItem key="hacker" value="hacker">
                {t('hacker')}
              </MenuItem>
              <MenuItem key="insider-accidental" value="insider-accidental">
                {t('insider-accidental')}
              </MenuItem>
              <MenuItem key="insider-disgruntled" value="insider-disgruntled">
                {t('insider-disgruntled')}
              </MenuItem>
              <MenuItem key="nation-state" value="nation-state">
                {t('nation-state')}
              </MenuItem>
              <MenuItem key="sensationalist" value="sensationalist">
                {t('sensationalist')}
              </MenuItem>
              <MenuItem key="spy" value="spy">
                {t('spy')}
              </MenuItem>
              <MenuItem key="terrorist" value="terrorist">
                {t('terrorist')}
              </MenuItem>
              <MenuItem key="unknown" value="unknown">
                {t('unknown')}
              </MenuItem>
            </Field>
            <ConfidenceField
              name="confidence"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Confidence')}
              fullWidth={true}
              containerstyle={{ width: '100%', marginTop: 20 }}
              editContext={context}
              variant="edit"
            />
            <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            <CreatedByField
              name="createdBy"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={this.handleChangeCreatedBy.bind(this)}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldname="objectMarking"
                />
              }
              onChange={this.handleChangeObjectMarking.bind(this)}
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                validateForm={validateForm}
              />
            )}
          </Form> */}
          </>
        )}
      </Formik>
    );
  }
}

DeviceEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  device: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const DeviceEditionOverview = createFragmentContainer(
  DeviceEditionOverviewComponent,
  {
    device: graphql`
      fragment DeviceEditionOverview_device on ThreatActor {
        id
        name
        threat_actor_types
        confidence
        description
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
              definition_type
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
)(DeviceEditionOverview);
