import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
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
import CoverageInformationField from '../../common/form/CoverageInformationField';

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
  confidence: number | null;
  coverage_information: { coverage_name: string; coverage_score: number | string }[];
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

  // const [commitRelationAdd] = useApiMutation(securityCoverageMutationRelationAdd);
  // const [commitRelationDelete] = useApiMutation(securityCoverageMutationRelationDelete);
  // const [commitFieldPatch] = useApiMutation(securityCoverageMutationFieldPatch);
  // const [commitEditionFocus] = useApiMutation(securityCoverageEditionOverviewFocus);

  const queries = {
    fieldPatch: securityCoverageMutationFieldPatch,
    editionFocus: securityCoverageEditionOverviewFocus,
    relationAdd: securityCoverageMutationRelationAdd,
    relationDelete: securityCoverageMutationRelationDelete,
  };
  const { mandatoryAttributes } = useIsMandatoryAttribute(SECURITY_COVERAGE_TYPE);

  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    coverage_information: Yup.array().of(
      Yup.object().shape({
        coverage_name: Yup.string().required(t_i18n('This field is required')),
        coverage_score: Yup.number()
          .required(t_i18n('This field is required'))
          .min(0, t_i18n('Score must be at least 0'))
          .max(100, t_i18n('Score must be at most 100')),
      }),
    ).nullable(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);

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
    value: FieldOption | string | FieldOption[] | number | number[] | null,
  ) => {
    securityValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        editor.fieldPatch({
          variables: {
            id: securityCoverageData.id,
            input: [{ key: name, value: value ?? '' }],
          },
        });
      })
      .catch(() => false);
  };

  const initialValues: SecurityCoverageEditionFormValues = {
    name: securityCoverageData.name,
    description: securityCoverageData.description ?? null,
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
        <Form style={{ margin: '20px 0 20px 0' }}>
          <AlertConfidenceForEntity entity={securityCoverageData} />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
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
            entityType="Security-Converage"
            onFocus={editor.changeFocus}
            onSubmit={(name, value) => handleSubmitField(name, (value ?? '').toString())}
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <CoverageInformationField
            name="coverage_information"
            values={values.coverage_information}
            setFieldValue={setFieldValue}
          />
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
        </Form>
      )}
    </Formik>
  );
};

export default SecurityCoverageEditionOverview;
