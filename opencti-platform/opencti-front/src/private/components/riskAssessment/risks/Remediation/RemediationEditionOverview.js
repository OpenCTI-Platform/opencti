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
import AssetTaglist from '../../../common/form/AssetTaglist';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import { SubscriptionFocus } from '../../../../../components/Subscription';
import { commitMutation } from '../../../../../relay/environment';
import CreatedByField from '../../../common/form/CreatedByField';
import AssetType from '../../../common/form/AssetType';
import ObjectMarkingField from '../../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../../components/MarkDownField';
import SelectField from '../../../../../components/SelectField';
import ConfidenceField from '../../../common/form/ConfidenceField';
import CommitMessage from '../../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../../utils/String';
import CyioCoreObjectLabelsView from '../../../common/stix_core_objects/CyioCoreObjectLabelsView';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
});

const remediationMutationFieldPatch = graphql`
  mutation RemediationEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
  ) {
    threatActorEdit(id: $id) {
      fieldPatch(input: $input, commitMessage: $commitMessage) {
        ...RemediationEditionOverview_remediation
        # ...Device_device
      }
    }
  }
`;

export const remediationEditionOverviewFocus = graphql`
  mutation RemediationEditionOverviewFocusMutation(
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

const remediationMutationRelationAdd = graphql`
  mutation RemediationEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    threatActorEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...RemediationEditionOverview_remediation
        }
      }
    }
  }
`;

const remediationMutationRelationDelete = graphql`
  mutation RemediationEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    threatActorEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...RemediationEditionOverview_remediation
      }
    }
  }
`;

const remediationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  threat_actor_types: Yup.array(),
  confidence: Yup.number().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class RemediationEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: remediationEditionOverviewFocus,
      variables: {
        id: this.props.remediation.id,
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
      mutation: remediationMutationFieldPatch,
      variables: {
        id: this.props.remediation.id,
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
      remediationValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: remediationMutationFieldPatch,
            variables: {
              id: this.props.remediation.id,
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
        mutation: remediationMutationFieldPatch,
        variables: {
          id: this.props.remediation.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    if (!this.props.enableReferences) {
      const { remediation } = this.props;
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(remediation);

      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);

      if (added.length > 0) {
        commitMutation({
          mutation: remediationMutationRelationAdd,
          variables: {
            id: this.props.remediation.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }

      if (removed.length > 0) {
        commitMutation({
          mutation: remediationMutationRelationDelete,
          variables: {
            id: this.props.remediation.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  }

  render() {
    const {
      t,
      classes,
      remediation,
      context,
      enableReferences,
    } = this.props;
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    const createdBy = R.pathOr(null, ['createdBy', 'name'], remediation) === null
      ? ''
      : {
        label: R.pathOr(null, ['createdBy', 'name'], remediation),
        value: R.pathOr(null, ['createdBy', 'id'], remediation),
      };
    const killChainPhases = R.pipe(
      R.pathOr([], ['killChainPhases', 'edges']),
      R.map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
      })),
    )(remediation);
    const objectMarking = R.pipe(
      R.pathOr([], ['objectMarking', 'edges']),
      R.map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(remediation);

    const initialValues = R.pipe(
      R.assoc('id', remediation.id),
      R.assoc('asset_id', remediation.asset_id),
      R.assoc('description', remediation.description),
      R.assoc('name', remediation.name),
      R.assoc('asset_tag', remediation.asset_tag),
      R.assoc('asset_type', remediation.asset_type),
      R.assoc('location', remediation.locations.map((index) => [index.description]).join('\n')),
      R.assoc('version', remediation.version),
      R.assoc('vendor_name', remediation.vendor_name),
      R.assoc('serial_number', remediation.serial_number),
      R.assoc('release_date', remediation.release_date),
      R.assoc('operational_status', remediation.operational_status),
      R.pick([
        'id',
        'asset_id',
        'name',
        'description',
        'asset_tag',
        'asset_type',
        'location',
        'version',
        'vendor_name',
        'serial_number',
        'release_date',
        'operational_status',
      ]),
    )(remediation);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={remediationValidation(t)}
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
                          variant='outlined'
                          size='small'
                          name="id"
                          fullWidth={true}
                          containerstyle={{ width: '100%' }}
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
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
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant='outlined'
                          size='small'
                          name="asset_id"
                          fullWidth={true}
                          containerstyle={{ width: '100%' }}
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
                        />
                      </div>
                      {/* <div>
                      <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ float: 'left' }}
                      >
                        {t('Description')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-3px 0 0 8px' }}>
                        <Tooltip title={t('Description')} >
                          <Information fontSize="small" color="primary" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <textarea className="scrollbar-customize" rows="3" cols="24" />
                    </div> */}
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 17 }}
                        >
                          {t('Description')}
                        </Typography>
                        <div style={{ float: 'left', margin: '17px 0 0 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        {/* <div className="clearfix" />
                      <textarea className="scrollbar-customize" rows="3" cols="24" /> */}
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="Description"
                          fullWidth={true}
                          multiline={true}
                          rows="3"
                          variant='outlined'
                          />
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
                          variant='outlined'
                          size='small'
                          name="version"
                          fullWidth={true}
                          containerstyle={{ width: '100%' }}
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
                          variant='outlined'
                          size='small'
                          name="serial_number"
                          fullWidth={true}
                          containerstyle={{ width: '100%' }}
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
                          variant='outlined'
                          name="ports"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        // helperText={
                        //   <SubscriptionFocus
                        //   context={context}
                        //   fieldName="ports"
                        //   />
                        // }
                        />
                        <Field
                          component={SelectField}
                          variant='outlined'
                          name="ports"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        // helperText={
                        //   <SubscriptionFocus
                        //   context={context}
                        //   fieldName="ports"
                        //   />
                        // }
                        />
                        <Field
                          component={SelectField}
                          variant='outlined'
                          name="ports"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        // helperText={
                        //   <SubscriptionFocus
                        //   context={context}
                        //   fieldName="ports"
                        //   />
                        // }
                        />
                        <Field
                          component={SelectField}
                          variant='outlined'
                          name="ports"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        // helperText={
                        //   <SubscriptionFocus
                        //   context={context}
                        //   fieldName="ports"
                        //   />
                        // }
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
                        <CyioCoreObjectLabelsView
                          labels={objectLabel}
                          marginTop={20}
                          id={remediation.id}
                        />
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
                          <Tooltip title={t('Asset Type')}>
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <AssetType
                          component={SelectField}
                          variant='outlined'
                          name="asset_type"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                          helperText={t('Select Asset Type')}
                        >
                        </AssetType>
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
                          <Tooltip title={t('Asset Tag')}>
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <AssetTaglist
                          component={SelectField}
                          variant='outlined'
                          name="asset_tag"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        >
                        </AssetTaglist>
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
                          <Tooltip title={t('Location')}>
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                        component={TextField}
                        name="Location"
                        fullWidth={true}
                        multiline={true}
                        rows="3"
                        variant='outlined'
                        />
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
                          <Tooltip title={t('Vendor Name')}>
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          variant='outlined'
                          name="vendor_name"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
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
                          {t('Release Date')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Release Date')}>
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          variant='outlined'
                          name="release_date"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        // helperText={
                        //   <SubscriptionFocus
                        //   context={context}
                        //   fieldName="ReleaseDate"
                        //   />
                        // }
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Operational State')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Operation State')}>
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          variant='outlined'
                          name="operational_status"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
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

RemediationEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  remediation: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const RemediationEditionOverview = createFragmentContainer(
  RemediationEditionOverviewComponent,
  {
    remediation: graphql`
      fragment RemediationEditionOverview_remediation on ThreatActor {
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
)(RemediationEditionOverview);
