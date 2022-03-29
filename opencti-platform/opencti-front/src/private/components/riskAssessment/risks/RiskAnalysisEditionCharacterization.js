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
    padding: '0 24px',
    borderRadius: 6,
  },
  header: {
    borderBottom: '1px solid white',
    padding: '22px 0 13px 0',
  },
  headerText: {
    paddingLeft: '16px',
    textTransform: 'capitalize',
  },
});

const riskAnalysisEditionCharacterizationMutationFieldPatch = graphql`
  mutation RiskAnalysisEditionCharacterizationFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    editRisk(id: $id, input: $input) {
        id
       # ...RiskEditionOverview_risk
       # ...Risk_risk
    }
  }
`;

export const riskAnalysisEditionCharacterizationFocus = graphql`
  mutation RiskAnalysisEditionCharacterizationFocusMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    editRisk(id: $id, input: $input) {
      id
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
//           ...RiskEditionOverview_risk
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
//         ...RiskEditionOverview_risk
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

class RiskAnalysisEditionCharacterizationComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: riskAnalysisEditionCharacterizationFocus,
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
      R.assoc('priority', values.priority),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    console.log('riskEditionOverviewSubmit', inputValues);
    commitMutation({
      mutation: riskAnalysisEditionCharacterizationMutationFieldPatch,
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
            mutation: riskAnalysisEditionCharacterizationMutationFieldPatch,
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
        mutation: riskAnalysisEditionCharacterizationMutationFieldPatch,
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
    // const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    // const createdBy = R.pathOr(null, ['createdBy', 'name'], risk) === null
    //   ? ''
    //   : {
    //     label: R.pathOr(null, ['createdBy', 'name'], risk),
    //     value: R.pathOr(null, ['createdBy', 'id'], risk),
    //   };
    // const killChainPhases = R.pipe(
    //   R.pathOr([], ['killChainPhases', 'edges']),
    //   R.map((n) => ({
    //     label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
    //     value: n.node.id,
    //   })),
    // )(risk);
    // const objectMarking = R.pipe(
    //   R.pathOr([], ['objectMarking', 'edges']),
    //   R.map((n) => ({
    //     label: n.node.definition,
    //     value: n.node.id,
    //   })),
    // )(risk);

    const initialValues = R.pipe(
      R.assoc('id', risk?.id || ''),
      R.assoc('item_id', risk?.item_id || ''),
      R.assoc('description', risk?.description || ''),
      R.assoc('weakness', risk?.weakness || ''),
      R.assoc('controls', risk?.controls || []),
      R.assoc('risk_rating', risk?.risk_rating || ''),
      R.assoc('priority', risk?.priority || 2),
      R.assoc('impact', risk?.impact || ''),
      R.assoc('likelihood', risk?.likelihood || ''),
      R.assoc('responsible_parties', risk?.responsible_parties || []),
      R.assoc('labels', risk?.labels || []),
      R.pick([
        'id',
        'item_id',
        'description',
        'weakness',
        'controls',
        'risk_rating',
        'priority',
        'impact',
        'likelihood',
        'responsible_parties',
        'labels',
      ]),
    )(risk);
    console.log('RiskEditionContainerRisk', risk);
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
            <div style={{ height: '100%' }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Characterization')}
              </Typography>
              <Paper className={ classes.paper } elevation={2}>
                <Grid container={true} className={classes.header}>
                  <Grid item={true} xs={4}>
                    <Typography
                      variant="h2"
                      gutterBottom={true}
                      className={classes.headerText}
                    >
                      {t('Name')}
                    </Typography>
                  </Grid>
                  <Grid item={true} xs={4}>
                    <Typography
                      variant="h2"
                      gutterBottom={true}
                      className={classes.headerText}
                    >
                      {t('Value')}
                    </Typography>
                  </Grid>
                  <Grid item={true} xs={4}>
                    <Typography
                      variant="h2"
                      gutterBottom={true}
                      className={classes.headerText}
                    >
                      {t('Detection Source')}
                    </Typography>
                  </Grid>
                </Grid>
                <Grid container={true} style={{ padding: '15px 0', borderBottom: '1px solid grey' }}>
                  <Grid item={true} xs={4}>
                    <Field
                      component={TextField}
                      variant='outlined'
                      size='small'
                      name="likelihood"
                      fullWidth={true}
                      style={{ width: '90%' }}
                      containerstyle={{ width: '100%' }}
                    />
                  </Grid>
                  <Grid item={true} xs={4}>
                    <Field
                      component={TextField}
                      variant='outlined'
                      size='small'
                      name="likelihood"
                      fullWidth={true}
                      style={{ width: '90%' }}
                      containerstyle={{ width: '100%' }}
                    />
                  </Grid>
                  <Grid item={true} xs={4}>
                    <Field
                      component={TextField}
                      variant='outlined'
                      size='small'
                      name="likelihood"
                      fullWidth={true}
                      style={{ width: '90%' }}
                      containerstyle={{ width: '100%' }}
                    />
                  </Grid>
                </Grid>
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
              label={t('Risk types')}
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

RiskAnalysisEditionCharacterizationComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  risk: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const RiskAnalysisEditionCharacterization = createFragmentContainer(
  RiskAnalysisEditionCharacterizationComponent,
  {
    risk: graphql`
      fragment RiskAnalysisEditionCharacterization_risk on POAMItem {
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
                    actor_ref {
                      ... on AssessmentPlatform {
                        id
                        name
                      }
                      ... on Component {
                        id
                        component_type
                        name
                      }
                      ... on OscalParty {
                        id
                        party_type
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
                subject_ref {
                  ... on Component {
                    id
                    component_type
                    name          #Impacted
                  }
                  ... on InventoryItem {
                    id
                    asset_type
                    name
                  }
                  ... on OscalLocation {
                    id
                    entity_type
                    name
                  }
                  ... on OscalParty {
                    id
                    entity_type
                    name
                  }
                  ... on OscalUser {
                    id
                    entity_type
                    name
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
)(RiskAnalysisEditionCharacterization);
