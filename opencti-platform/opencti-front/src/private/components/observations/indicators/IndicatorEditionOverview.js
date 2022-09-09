import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import SwitchField from '../../../../components/SwitchField';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import ConfidenceField from '../../common/form/ConfidenceField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import {
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/Edition';
import StatusField from '../../common/form/StatusField';
import { buildDate, parse } from '../../../../utils/Time';
import DateTimePickerField from '../../../../components/DateTimePickerField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '30px 30px 30px 30px',
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

const indicatorMutationFieldPatch = graphql`
  mutation IndicatorEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    indicatorEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...IndicatorEditionOverview_indicator
        ...Indicator_indicator
      }
    }
  }
`;

export const indicatorEditionOverviewFocus = graphql`
  mutation IndicatorEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    indicatorEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const indicatorMutationRelationAdd = graphql`
  mutation IndicatorEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    indicatorEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...IndicatorEditionOverview_indicator
        }
      }
    }
  }
`;

const indicatorMutationRelationDelete = graphql`
  mutation IndicatorEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    indicatorEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...IndicatorEditionOverview_indicator
      }
    }
  }
`;

const indicatorValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  confidence: Yup.number(),
  pattern: Yup.string().required(t('This field is required')),
  valid_from: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  valid_until: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  x_opencti_score: Yup.number().nullable(),
  description: Yup.string().nullable(),
  x_opencti_detection: Yup.boolean(),
  x_mitre_platforms: Yup.array(),
  indicator_types: Yup.array(),
  references: Yup.array().required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
});

class IndicatorEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: indicatorEditionOverviewFocus,
      variables: {
        id: this.props.indicator.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  onSubmit(values, { setSubmitting }) {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc(
        'valid_from',
        values.valid_from ? parse(values.valid_from).format() : null,
      ),
      R.assoc(
        'valid_until',
        values.valid_from ? parse(values.valid_until).format() : null,
      ),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: indicatorMutationFieldPatch,
      variables: {
        id: this.props.indicator.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        this.props.handleClose();
      },
    });
  }

  handleSubmitField(name, value) {
    if (!this.props.enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      indicatorValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: indicatorMutationFieldPatch,
            variables: {
              id: this.props.indicator.id,
              input: {
                key: name,
                value: finalValue ?? '',
              },
            },
          });
        })
        .catch(() => false);
    }
  }

  handleChangeKillChainPhases(name, values) {
    if (!this.props.enableReferences) {
      const { indicator } = this.props;
      const currentKillChainPhases = R.pipe(
        R.pathOr([], ['killChainPhases', 'edges']),
        R.map((n) => ({
          label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
          value: n.node.id,
        })),
      )(indicator);
      const added = R.difference(values, currentKillChainPhases);
      const removed = R.difference(currentKillChainPhases, values);
      if (added.length > 0) {
        commitMutation({
          mutation: indicatorMutationRelationAdd,
          variables: {
            id: this.props.indicator.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'kill-chain-phase',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: indicatorMutationRelationDelete,
          variables: {
            id: this.props.indicator.id,
            toId: R.head(removed).value,
            relationship_type: 'kill-chain-phase',
          },
        });
      }
    }
  }

  handleChangeCreatedBy(name, value) {
    if (!this.props.enableReferences) {
      commitMutation({
        mutation: indicatorMutationRelationDelete,
        variables: {
          id: this.props.indicator.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    if (!this.props.enableReferences) {
      const { indicator } = this.props;
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(indicator);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);
      if (added.length > 0) {
        commitMutation({
          mutation: indicatorMutationRelationAdd,
          variables: {
            id: this.props.indicator.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: indicatorMutationRelationDelete,
          variables: {
            id: this.props.indicator.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  }

  render() {
    const { t, indicator, context, enableReferences } = this.props;
    const killChainPhases = R.pipe(
      R.pathOr([], ['killChainPhases', 'edges']),
      R.map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
      })),
    )(indicator);
    const createdBy = convertCreatedBy(indicator);
    const objectMarking = convertMarkings(indicator);
    const status = convertStatus(t, indicator);
    const initialValues = R.pipe(
      R.assoc('killChainPhases', killChainPhases),
      R.assoc('createdBy', createdBy),
      R.assoc('objectMarking', objectMarking),
      R.assoc('x_opencti_workflow_id', status),
      R.assoc(
        'x_mitre_platforms',
        R.propOr([], 'x_mitre_platforms', indicator),
      ),
      R.assoc('indicator_types', R.propOr([], 'indicator_types', indicator)),
      R.assoc('valid_from', buildDate(indicator.valid_from)),
      R.assoc('valid_until', buildDate(indicator.valid_until)),
      R.pick([
        'name',
        'confidence',
        'pattern',
        'description',
        'valid_from',
        'valid_until',
        'x_opencti_score',
        'x_opencti_detection',
        'indicator_types',
        'x_mitre_platforms',
        'killChainPhases',
        'createdBy',
        'killChainPhases',
        'objectMarking',
        'x_opencti_workflow_id',
      ]),
    )(indicator);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={indicatorValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
      >
        {({
          submitForm,
          isSubmitting,
          validateForm,
          setFieldValue,
          values,
        }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
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
              component={TextField}
              variant="standard"
              name="pattern"
              label={t('Indicator pattern')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="pattern" />
              }
            />
            <Field
              component={DateTimePickerField}
              name="valid_from"
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              TextFieldProps={{
                label: t('Valid from'),
                variant: 'standard',
                fullWidth: true,
                style: { marginTop: 20 },
                helperText: (
                  <SubscriptionFocus context={context} fieldName="valid_from" />
                ),
              }}
            />
            <Field
              component={DateTimePickerField}
              name="valid_until"
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              TextFieldProps={{
                label: t('Valid until'),
                variant: 'standard',
                fullWidth: true,
                style: { marginTop: 20 },
                helperText: (
                  <SubscriptionFocus
                    context={context}
                    fieldName="valid_until"
                  />
                ),
              }}
            />
            <OpenVocabField
              label={t('Indicator types')}
              type="indicator-type-ov"
              name="indicator_types"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              containerstyle={{ marginTop: 20, width: '100%' }}
              variant="edit"
              multiple={true}
              editContext={context}
            />
            <Field
              component={SelectField}
              variant="standard"
              name="x_mitre_platforms"
              multiple={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Platforms')}
              fullWidth={true}
              containerstyle={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_mitre_platforms"
                />
              }
            >
              <MenuItem value="Android">{t('Android')}</MenuItem>
              <MenuItem value="macOS">{t('macOS')}</MenuItem>
              <MenuItem value="Linux">{t('Linux')}</MenuItem>
              <MenuItem value="Windows">{t('Windows')}</MenuItem>
            </Field>
            <Field
              component={TextField}
              variant="standard"
              name="x_opencti_score"
              label={t('Score')}
              type="number"
              fullWidth={true}
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_opencti_score"
                />
              }
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
            <KillChainPhasesField
              name="killChainPhases"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="killChainPhases"
                />
              }
              onChange={this.handleChangeKillChainPhases.bind(this)}
            />
            {indicator.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Indicator"
                onFocus={this.handleChangeFocus.bind(this)}
                onChange={this.handleSubmitField.bind(this)}
                setFieldValue={setFieldValue}
                style={{ marginTop: 20 }}
                helpertext={
                  <SubscriptionFocus
                    context={context}
                    fieldName="x_opencti_workflow_id"
                  />
                }
              />
            )}
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
            <Field
              component={SwitchField}
              type="checkbox"
              name="x_opencti_detection"
              label={t('Detection')}
              containerstyle={{ marginTop: 20 }}
              onChange={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_opencti_detection"
                />
              }
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                validateForm={validateForm}
                setFieldValue={setFieldValue}
                values={values}
                id={indicator.id}
              />
            )}
          </Form>
        )}
      </Formik>
    );
  }
}

IndicatorEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  indicator: PropTypes.object,
  context: PropTypes.array,
};

const IndicatorEditionOverview = createFragmentContainer(
  IndicatorEditionOverviewComponent,
  {
    indicator: graphql`
      fragment IndicatorEditionOverview_indicator on Indicator {
        id
        name
        confidence
        description
        pattern
        valid_from
        valid_until
        revoked
        x_opencti_score
        x_opencti_detection
        x_mitre_platforms
        indicator_types
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        killChainPhases {
          edges {
            node {
              id
              kill_chain_name
              phase_name
              x_opencti_order
            }
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
        status {
          id
          order
          template {
            name
            color
          }
        }
        workflowEnabled
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IndicatorEditionOverview);
