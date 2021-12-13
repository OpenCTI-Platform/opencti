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
import AddIcon from '@material-ui/icons/Add';
// import AssetTaglist from '../../common/form/AssetTaglist';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import AssetType from '../../common/form/AssetType';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StixCoreObjectLabelsView from '../../common/stix_core_objects/StixCoreObjectLabelsView';

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
  mutation RiskTrackingLogEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
  ) {
    threatActorEdit(id: $id) {
      fieldPatch(input: $input, commitMessage: $commitMessage) {
        id
       # ...RiskTrackingLogEdition_risk
       # ...Risk_risk
      }
    }
  }
`;

export const riskTrackingLogEditionFocus = graphql`
  mutation RiskTrackingLogEditionFocusMutation(
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

// const riskMutationRelationAdd = graphql`
//   mutation RiskEditionOverviewRelationAddMutation(
//     $id: ID!
//     $input: StixMetaRelationshipAddInput
//   ) {
//     threatActorEdit(id: $id) {
//       relationAdd(input: $input) {
//         from {
//           ...RiskTrackingLogEdition_risk
//         }
//       }
//     }
//   }
// `;

// const riskMutationRelationDelete = graphql`
//   mutation RiskEditionOverviewRelationDeleteMutation(
//     $id: ID!
//     $toId: String!
//     $relationship_type: String!
//   ) {
//     threatActorEdit(id: $id) {
//       relationDelete(toId: $toId, relationship_type: $relationship_type) {
//         ...RiskTrackingLogEdition_risk
//       }
//     }
//   }
// `;

const riskValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  threat_actor_types: Yup.array(),
  confidence: Yup.number().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class RiskTrackingLogEditionComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: riskTrackingLogEditionFocus,
      variables: {
        id: this.props.risk?.id,
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
      mutation: riskMutationFieldPatch,
      variables: {
        id: this.props.risk?.id,
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
      riskValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: riskMutationFieldPatch,
            variables: {
              id: this.props.risk?.id,
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
        mutation: riskMutationFieldPatch,
        variables: {
          id: this.props.risk?.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    if (!this.props.enableReferences) {
      const { risk } = this.props;
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(risk);

      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);

      if (added.length > 0) {
        commitMutation({
          // mutation: riskMutationRelationAdd,
          variables: {
            id: this.props.risk?.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }

      if (removed.length > 0) {
        commitMutation({
          // mutation: riskMutationRelationDelete,
          variables: {
            id: this.props.risk?.id,
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
      risk,
      context,
      enableReferences,
    } = this.props;
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    const createdBy = R.pathOr(null, ['createdBy', 'name'], risk) === null
      ? ''
      : {
        label: R.pathOr(null, ['createdBy', 'name'], risk),
        value: R.pathOr(null, ['createdBy', 'id'], risk),
      };
    const killChainPhases = R.pipe(
      R.pathOr([], ['killChainPhases', 'edges']),
      R.map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
      })),
    )(risk);
    const objectMarking = R.pipe(
      R.pathOr([], ['objectMarking', 'edges']),
      R.map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(risk);

    const initialValues = R.pipe(
      R.assoc('id', risk?.id),
      R.assoc('asset_id', risk?.asset_id),
      R.assoc('description', risk?.description),
      R.assoc('name', risk?.name),
      R.assoc('asset_tag', risk?.asset_tag),
      R.assoc('asset_type', risk?.asset_type),
      R.assoc('location', risk?.locations?.map((index) => [index.description]).join('\n')),
      R.assoc('version', risk?.version),
      R.assoc('vendor_name', risk?.vendor_name),
      R.assoc('serial_number', risk?.serial_number),
      R.assoc('release_date', risk?.release_date),
      R.assoc('operational_status', risk?.operational_status),
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
    )(risk);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={riskValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
      >
        {({
          submitForm, isSubmitting, validateForm, setFieldValue,
        }) => (
          <>
            <Grid spacing={3} container={true}>
              <Grid item={true} xs={4}>
                <Grid style={{ marginBottom: '15px' }} item={true}>
                  <Typography
                    variant="subtitle2"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Risk Status')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
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
                    style={{ height: '38.09px', marginBottom: '3px' }}
                    containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                  />
                </Grid>
                <Grid item={true}>
                  <Typography
                    variant="subtitle2"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Start Date')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    variant='outlined'
                    size='small'
                    name="asset_id"
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  />
                </Grid>
              </Grid>
              <Grid item={true} xs={4}>
                <Grid style={{ marginBottom: '20px' }} item={true}>
                  <Typography
                    variant="subtitle2"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Title')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    variant='outlined'
                    size='small'
                    name="asset_id"
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  />
                </Grid>
                <Grid style={{ marginBottom: '20px' }} item={true}>
                  <Typography
                    variant="subtitle2"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('End Date')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    variant='outlined'
                    size='small'
                    name="asset_id"
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  />
                </Grid>
              </Grid>
              <Grid item={true} xs={4}>
                <Typography
                  variant="subtitle2"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Impacted Component')}
                </Typography>
                <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                  <Tooltip
                    title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  name="Description"
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  variant='outlined'
                />
              </Grid>
            </Grid>
            <Grid spacing={3} container={true}>
              <Grid item={true} xs={4}>
                <Grid style={{ marginBottom: '15px' }} item={true}>
                  <Typography
                    variant="subtitle2"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Logged By')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
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
                    containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                  />
                  <Field
                    component={SelectField}
                    variant='outlined'
                    name="ports"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                  />
                </Grid>
              </Grid>
              <Grid item={true} xs={4}>
                <Grid style={{ marginBottom: '15px' }} item={true}>
                  <Typography
                    variant="subtitle2"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Status Change')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
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
                    style={{ height: '38.09px', marginBottom: '3px' }}
                    containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                  />
                </Grid>
              </Grid>
              <Grid item={true} xs={3}>
                <Grid style={{ marginBottom: '20px' }} item={true}>
                  <Typography
                    variant="subtitle2"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Related Response')}
                  </Typography>
                  <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                    <Tooltip
                      title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    variant='outlined'
                    size='small'
                    name="asset_id"
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  />
                </Grid>
              </Grid>
            </Grid>
          </>
        )}
      </Formik>
    );
  }
}

RiskTrackingLogEditionComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  risk: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const RiskTrackingLogEdition = createFragmentContainer(
  RiskTrackingLogEditionComponent,
  {
    risk: graphql`
      fragment RiskTrackingLogEdition_risk on Risk {
        id
        created
        modified
        risk_log(first: 5) {
          edges {
            node {
              id
              created
              modified
              entry_type        # Entry Type
              name              # Title
              description       # Description
              event_start       # Start Date
              event_end         # End Date
              status_change     # Status Change
              logged_by {
                ... on OscalPerson {
                  id
                  name
                }
                ... on OscalOrganization {
                  id
                  name
                }
              }
              related_responses {
                id
                name
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
)(RiskTrackingLogEdition);
