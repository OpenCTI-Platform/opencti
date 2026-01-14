import React, { FunctionComponent } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import SwitchField from '../../../../components/fields/SwitchField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import ConfidenceField from '../../common/form/ConfidenceField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import { convertCreatedBy, convertKillChainPhases, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { buildDate, parse } from '../../../../utils/Time';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import { useDynamicSchemaEditionValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import { GenericContext } from '@components/common/model/GenericContextModel';
import { IndicatorEditionOverview_indicator$data } from '@components/observations/indicators/__generated__/IndicatorEditionOverview_indicator.graphql';
import { ExternalReferencesValues } from '@components/common/form/ExternalReferencesField';
import { FormikConfig } from 'formik/dist/types';

const indicatorMutationFieldPatch = graphql`
  mutation IndicatorEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
    $commitMessage: String
    $references: [String]
  ) {
    indicatorFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...IndicatorEditionOverview_indicator
      ...Indicator_indicator
    }
  }
`;

export const indicatorEditionOverviewFocus = graphql`
  mutation IndicatorEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    indicatorContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const indicatorMutationRelationAdd = graphql`
  mutation IndicatorEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    indicatorRelationAdd(id: $id, input: $input) {
      from {
        ...IndicatorEditionOverview_indicator
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
    indicatorRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
      ...IndicatorEditionOverview_indicator
    }
  }
`;

const INDICATOR_TYPE = 'Indicator';
type IndicatorGenericData = IndicatorEditionOverview_indicator$data & GenericData;

interface IndicatorEditionOverviewComponentProps {
  indicator: IndicatorGenericData;
  enableReferences: boolean;
  context?: readonly (GenericContext | null)[] | null;
  handleClose: () => void;
}

interface IndicatorEditionFormData {
  message?: string;
  createdBy?: FieldOption;
  objectMarking?: FieldOption[];
  x_opencti_workflow_id: FieldOption;
  killChainPhases?: FieldOption[];
  valid_from?: Date | string | null;
  valid_until?: Date | string | null;
  references: ExternalReferencesValues | undefined;
}

const IndicatorEditionOverviewComponent: FunctionComponent<IndicatorEditionOverviewComponentProps> = ({
  indicator,
  handleClose,
  context,
  enableReferences,
}) => {
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(INDICATOR_TYPE);

  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    indicator_types: Yup.array(),
    x_opencti_reliability: Yup.string().nullable(),
    confidence: Yup.number(),
    pattern: Yup.string().trim(),
    valid_from: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    valid_until: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .test('is-greater', t_i18n('The valid until date must be greater than the valid from date'), function isGreater(value) {
        const { valid_from } = this.parent;
        return !valid_from || !value || value > valid_from;
      }),
    x_mitre_platforms: Yup.array().nullable(),
    x_opencti_score: Yup.number().integer(t_i18n('The value must be an integer'))
      .required(t_i18n('This field is required'))
      .min(0, t_i18n('The value must be greater than or equal to 0'))
      .max(100, t_i18n('The value must be less than or equal to 100')),
    description: Yup.string().nullable(),
    x_opencti_detection: Yup.boolean(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
    killChainPhases: Yup.array().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);

  const indicatorValidator = useDynamicSchemaEditionValidation(
    mandatoryAttributes,
    basicShape,
  );

  const queries = {
    fieldPatch: indicatorMutationFieldPatch,
    relationAdd: indicatorMutationRelationAdd,
    relationDelete: indicatorMutationRelationDelete,
    editionFocus: indicatorEditionOverviewFocus,
  };
  const editor = useFormEditor(
    indicator,
    enableReferences,
    queries,
    indicatorValidator,
  );

  const onSubmit: FormikConfig<IndicatorEditionFormData>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
      killChainPhases: (values.killChainPhases ?? []).map(({ value }) => value),
      valid_from: values.valid_from
        ? parse(values.valid_from).format()
        : null,

      valid_until: values.valid_until
        ? parse(values.valid_until).format()
        : null,
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));

    editor.fieldPatch({
      variables: {
        id: indicator.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name: string, value: string | string[] | number | number[] | FieldOption | null) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as FieldOption).value;
      }
      indicatorValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: indicator.id,
              input: {
                key: name,
                value: finalValue ?? '',
              },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    name: indicator.name,
    confidence: indicator.confidence,
    pattern: indicator.pattern,
    description: indicator.description,
    x_opencti_score: indicator.x_opencti_score,
    x_opencti_detection: indicator.x_opencti_detection,
    indicator_types: indicator.indicator_types ?? [],
    x_mitre_platforms: indicator.x_mitre_platforms ?? [],
    x_opencti_reliability: indicator.x_opencti_reliability,
    valid_from: buildDate(indicator.valid_from),
    valid_until: buildDate(indicator.valid_until),
    killChainPhases: convertKillChainPhases(indicator),
    createdBy: convertCreatedBy(indicator) as FieldOption,
    objectMarking: convertMarkings(indicator),
    x_opencti_workflow_id: convertStatus(t_i18n, indicator) as FieldOption,
    references: [],
  };

  return (
    <Formik<IndicatorEditionFormData>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={indicatorValidator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
    >
      {({
        submitForm,
        isSubmitting,
        setFieldValue,
        values,
        isValid,
        dirty,
      }) => (
        <Form>
          <AlertConfidenceForEntity entity={indicator} />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <OpenVocabField
            label={t_i18n('Indicator types')}
            type="indicator-type-ov"
            name="indicator_types"
            required={(mandatoryAttributes.includes('indicator_types'))}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={true}
            editContext={context}
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Indicator"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <Field
            component={TextField}
            variant="standard"
            name="pattern"
            label={t_i18n('Indicator pattern')}
            required={(mandatoryAttributes.includes('pattern'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="pattern" />
            }
          />
          <OpenVocabField
            label={t_i18n('Reliability')}
            type="reliability_ov"
            name="x_opencti_reliability"
            required={(mandatoryAttributes.includes('x_opencti_reliability'))}
            onChange={(name, value) => setFieldValue(name, value)}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            multiple={false}
            editContext={context}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
          />
          <Field
            component={DateTimePickerField}
            name="valid_from"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            textFieldProps={{
              label: t_i18n('Valid from'),
              required: (mandatoryAttributes.includes('valid_from')),
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
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            textFieldProps={{
              label: t_i18n('Valid until'),
              required: (mandatoryAttributes.includes('valid_until')),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
              helperText: (
                <SubscriptionFocus context={context} fieldName="valid_until" />
              ),
            }}
          />
          <OpenVocabField
            label={t_i18n('Platforms')}
            type="platforms_ov"
            name="x_mitre_platforms"
            required={(mandatoryAttributes.includes('x_mitre_platforms'))}
            variant="edit"
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
            editContext={context}
          />
          <Field
            component={TextField}
            variant="standard"
            name="x_opencti_score"
            required={(mandatoryAttributes.includes('x_opencti_score'))}
            label={t_i18n('Score')}
            type="number"
            fullWidth={true}
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={(
              <SubscriptionFocus
                context={context}
                fieldName="x_opencti_score"
              />
            )}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          <KillChainPhasesField
            name="killChainPhases"
            required={(mandatoryAttributes.includes('killChainPhases'))}
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldName="killChainPhases" />
            }
            onChange={editor.changeKillChainPhases}
          />
          {indicator.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Indicator"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              setFieldValue={setFieldValue}
              style={{ marginTop: 20 }}
              helpertext={(
                <SubscriptionFocus
                  context={context}
                  fieldName="x_opencti_workflow_id"
                />
              )}
            />
          )}
          <CreatedByField
            name="createdBy"
            required={(mandatoryAttributes.includes('createdBy'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
            }
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={(mandatoryAttributes.includes('objectMarking'))}
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
            }
            setFieldValue={setFieldValue}
            onChange={editor.changeMarking}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="x_opencti_detection"
            label={t_i18n('Detection')}
            required={(mandatoryAttributes.includes('x_opencti_detection'))}
            containerstyle={{ marginTop: 20 }}
            onChange={handleSubmitField}
            helperText={(
              <SubscriptionFocus
                context={context}
                fieldName="x_opencti_detection"
              />
            )}
          />
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              setFieldValue={setFieldValue}
              open={false}
              values={values.references}
              id={indicator.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

IndicatorEditionOverviewComponent.propTypes = {
  theme: PropTypes.object,
  t: PropTypes.func,
  indicator: PropTypes.object,
  context: PropTypes.array,
  enableReferences: PropTypes.bool,
};

const IndicatorEditionOverview = createFragmentContainer(
  IndicatorEditionOverviewComponent,
  {
    indicator: graphql`
      fragment IndicatorEditionOverview_indicator on Indicator {
        id
        name
        confidence
        entity_type
        description
        pattern
        valid_from
        valid_until
        revoked
        x_opencti_score
        x_opencti_detection
        x_opencti_reliability
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
          id
          entity_type
          kill_chain_name
          phase_name
          x_opencti_order
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
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

export default IndicatorEditionOverview;
