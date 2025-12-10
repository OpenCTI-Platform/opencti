import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import ConfidenceField from '@components/common/form/ConfidenceField';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { adaptFieldValue } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';
import { SecurityCoverageEditionOverview_securityCoverage$key } from './__generated__/SecurityCoverageEditionOverview_securityCoverage.graphql';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import { convertCreatedBy, convertMarkings } from '../../../../utils/edition';
import { useDynamicSchemaEditionValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { CoverageInformationFieldEdit } from '../../common/form/CoverageInformationField';
import SwitchField from '../../../../components/fields/SwitchField';
import PeriodicityField from '../../../../components/fields/PeriodicityField';
import SelectField from '../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';
import OpenVocabField from '@components/common/form/OpenVocabField';

const SECURITY_COVERAGE_TYPE = 'Security-Coverage';

const securityCoverageMutationFieldPatch = graphql`
  mutation SecurityCoverageEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    securityCoverageFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...SecurityCoverageEditionOverview_securityCoverage
      ...SecurityCoverage_securityCoverage
    }
  }
`;

export const securityCoverageEditionOverviewFocus = graphql`
  mutation SecurityCoverageEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    securityCoverageContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const securityCoverageMutationRelationAdd = graphql`
  mutation SecurityCoverageEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    securityCoverageRelationAdd(id: $id, input: $input) {
      from {
        ...SecurityCoverageEditionOverview_securityCoverage
      }
    }
  }
`;

const securityCoverageMutationRelationDelete = graphql`
  mutation SecurityCoverageEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    securityCoverageRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      ...SecurityCoverageEditionOverview_securityCoverage
    }
  }
`;

const securityCoverageEditionOverviewFragment = graphql`
  fragment SecurityCoverageEditionOverview_securityCoverage on SecurityCoverage {
    id
    name
    description
    confidence
    external_uri
    periodicity
    duration
    type_affinity
    platforms_affinity
    auto_enrichment_disable
    coverage_information {
      coverage_name
      coverage_score
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
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
`;

interface SecurityCoverageEditionOverviewProps {
  securityCoverage: SecurityCoverageEditionOverview_securityCoverage$key;
  context: readonly ({
    readonly focusOn: string | null | undefined;
    readonly name: string;
  } | null)[] | null | undefined;
  enableReferences?: boolean;
}

interface SecurityCoverageEditionFormValues {
  name: string;
  description: string | null;
  periodicity: string | null;
  duration: string | null;
  type_affinity: string | null,
  platforms_affinity: readonly string[];
  external_uri: string | null;
  auto_enrichment_disable: boolean;
  confidence: number | null;
  coverage_information: { coverage_name: string; coverage_score: number }[];
  createdBy: FieldOption | null;
  objectMarking: FieldOption[];
}

const SecurityCoverageEditionOverview: FunctionComponent<SecurityCoverageEditionOverviewProps> = ({
  securityCoverage,
  context,
}) => {
  const { t_i18n } = useFormatter();

  const securityCoverageData = useFragment(
    securityCoverageEditionOverviewFragment,
    securityCoverage,
  );

  const queries = {
    fieldPatch: securityCoverageMutationFieldPatch,
    editionFocus: securityCoverageEditionOverviewFocus,
    relationAdd: securityCoverageMutationRelationAdd,
    relationDelete: securityCoverageMutationRelationDelete,
  };
  const { mandatoryAttributes } = useIsMandatoryAttribute(SECURITY_COVERAGE_TYPE);

  const baseShape = {
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    auto_enrichment_disable: Yup.boolean(),
    coverage_information: Yup.array().of(
      Yup.object().shape({
        coverage_name: Yup.string().required(t_i18n('This field is required')),
        coverage_score: Yup.number()
          .required(t_i18n('This field is required'))
          .min(0, t_i18n('Score must be at least 0'))
          .max(100, t_i18n('Score must be at most 100')),
      }),
    ).nullable(),
    periodicity: Yup.string().nullable(),
    duration: Yup.string().nullable(),
    type_affinity: Yup.string().nullable(),
    platforms_affinity: Yup.array(),
    external_uri: Yup.string().url().nullable(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  };
  const basicShape = yupShapeConditionalRequired(baseShape, mandatoryAttributes);

  const securityValidator = useDynamicSchemaEditionValidation(mandatoryAttributes, basicShape);
  const editor = useFormEditor(
    securityCoverageData as GenericData,
    false,
    queries,
    securityValidator,
  );

  const onSubmit: FormikConfig<SecurityCoverageEditionFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const inputValues = Object.entries({
      name: values.name,
      description: values.description,
      periodicity: values.periodicity,
      duration: values.duration,
      type_affinity: values.type_affinity,
      platforms_affinity: values.platforms_affinity,
      external_uri: values.external_uri,
      auto_enrichment_disable: values.auto_enrichment_disable,
      confidence: parseInt(String(values.confidence), 10),
      coverage_information: values.coverage_information?.map((info) => ({
        coverage_name: info.coverage_name,
        coverage_score: Number(info.coverage_score),
      })),
    }).map(([k, v]) => ({ key: k, value: adaptFieldValue(v) }));

    editor.fieldPatch({
      variables: {
        id: securityCoverageData.id,
        input: inputValues,
      },
      onCompleted: () => {
        setSubmitting(false);
      },
    });
  };

  const handleSubmitField = (
    name: string,
    value: FieldOption | string | FieldOption[] | number | number[] | null | object | object[],
  ) => {
    securityValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        editor.fieldPatch({
          variables: {
            id: securityCoverageData.id,
            input: [{ key: name, value: adaptFieldValue(value) ?? '' }],
          },
        });
      })
      .catch(() => false);
  };

  const initialValues: SecurityCoverageEditionFormValues = {
    name: securityCoverageData.name,
    description: securityCoverageData.description ?? null,
    external_uri: securityCoverageData.external_uri ?? null,
    periodicity: securityCoverageData.periodicity ?? null,
    duration: securityCoverageData.duration ?? null,
    type_affinity: securityCoverageData.type_affinity ?? null,
    platforms_affinity: securityCoverageData.platforms_affinity ?? [],
    auto_enrichment_disable: securityCoverageData.auto_enrichment_disable ?? false,
    confidence: securityCoverageData.confidence ?? null,
    coverage_information: (securityCoverageData.coverage_information ?? []).map((item) => ({
      coverage_name: item.coverage_name,
      coverage_score: item.coverage_score,
    })),
    createdBy: convertCreatedBy(securityCoverageData) as FieldOption,
    objectMarking: convertMarkings(securityCoverageData),
  };

  return (
    <Formik<SecurityCoverageEditionFormValues>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={securityValidator}
      onSubmit={onSubmit}
    >
      {({
        values,
        setFieldValue,
      }) => (
        <div style={{ margin: '20px 0 20px 0' }}>
          <AlertConfidenceForEntity entity={securityCoverageData} />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            required
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
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
          <ConfidenceField
            entityType="Security-Coverage"
            onFocus={editor.changeFocus}
            onSubmit={(name, value) => handleSubmitField(name, (value ?? '').toString())}
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <PeriodicityField
            name="periodicity"
            label={t_i18n('Coverage validity period')}
            style={fieldSpacingContainerStyle}
            handleOnChange={(duration) => handleSubmitField('periodicity', duration)}
            setFieldValue={setFieldValue}
          />
          <PeriodicityField
            name="duration"
            label={t_i18n('Duration')}
            style={fieldSpacingContainerStyle}
            handleOnChange={(duration) => handleSubmitField('duration', duration)}
            setFieldValue={setFieldValue}
          />
          <Field
            component={SelectField}
            variant="standard"
            name="type_affinity"
            onSubmit={handleSubmitField}
            onChange={(name: string, value: string) => setFieldValue(name, value)}
            label={t_i18n('Type affinity')}
            fullWidth={true}
            containerstyle={{ width: '100%', marginTop: 20 }}
          >
            <MenuItem key='ENDPOINT' value='ENDPOINT'>
              {t_i18n('Endpoint')}
            </MenuItem>
            <MenuItem key='CLOUD' value='CLOUD'>
              {t_i18n('Cloud')}
            </MenuItem>
            <MenuItem key='WEB' value='WEB'>
              {t_i18n('Web')}
            </MenuItem>
            <MenuItem key='TABLE-TOP' value='TABLE-TOP'>
              {t_i18n('Table-top')}
            </MenuItem>
          </Field>
          <OpenVocabField
            label={t_i18n('Platform(s) affinity')}
            type="platforms_ov"
            name="platforms_affinity"
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
            variant="edit"
          />
          <Field
            component={SwitchField}
            type="checkbox"
            onChange={handleSubmitField}
            name="auto_enrichment_disable"
            label={t_i18n('Force manual coverage (prevent enrichment connectors from running)')}
            containerstyle={fieldSpacingContainerStyle}
          />
          {values.auto_enrichment_disable && <>
            <CoverageInformationFieldEdit
              id={securityCoverageData.id}
              mode={'entity'}
              name="coverage_information"
              values={values.coverage_information}
            />
            <Field
              component={TextField}
              variant="standard"
              name="external_uri"
              onSubmit={handleSubmitField}
              label={t_i18n('Source external link')}
              fullWidth={true}
              style={fieldSpacingContainerStyle}
            />
          </>}
          <CreatedByField
            name="createdBy"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
            }
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldName="objectMarking" />
            }
            setFieldValue={setFieldValue}
            onChange={editor.changeMarking}
          />
        </div>
      )}
    </Formik>
  );
};

export default SecurityCoverageEditionOverview;
