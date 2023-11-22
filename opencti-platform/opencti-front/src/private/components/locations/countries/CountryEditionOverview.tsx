import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { CountryEditionOverview_country$key } from './__generated__/CountryEditionOverview_country.graphql';
import { Option } from '../../common/form/ReferenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { GenericContext } from '../../common/model/GenericContextModel';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const countryMutationFieldPatch = graphql`
  mutation CountryEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    countryEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...CountryEditionOverview_country
        ...Country_country
      }
    }
  }
`;

export const countryEditionOverviewFocus = graphql`
  mutation CountryEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    countryEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const countryMutationRelationAdd = graphql`
  mutation CountryEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    countryEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...CountryEditionOverview_country
        }
      }
    }
  }
`;

const countryMutationRelationDelete = graphql`
  mutation CountryEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    countryEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...CountryEditionOverview_country
      }
    }
  }
`;

const countryEditionOverviewFragment = graphql`
  fragment CountryEditionOverview_country on Country {
    id
    name
    description
    confidence
    entity_type
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

interface CountryEditionOverviewProps {
  countryRef: CountryEditionOverview_country$key;
  context?: readonly (GenericContext | null)[] | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface CountryEditionFormValues {
  name: string;
  description: string | null;
  confidence: number | undefined | null;
  createdBy: Option | undefined;
  objectMarking: Option[];
  x_opencti_workflow_id: Option;
  message?: string;
  references?: Option[];
}

const COUNTRY_TYPE = 'Country';

const CountryEditionOverviewComponent: FunctionComponent<
CountryEditionOverviewProps
> = ({ countryRef, context, enableReferences = false, handleClose }) => {
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    COUNTRY_TYPE,
  );
  const country = useFragment(countryEditionOverviewFragment, countryRef);
  const basicShape = {
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const countryValidator = useSchemaEditionValidation(COUNTRY_TYPE, basicShape);
  const queries = {
    fieldPatch: countryMutationFieldPatch,
    relationAdd: countryMutationRelationAdd,
    relationDelete: countryMutationRelationDelete,
    editionFocus: countryEditionOverviewFocus,
  };
  const editor = useFormEditor(
    country as GenericData,
    enableReferences,
    queries,
    countryValidator,
  );
  const onSubmit: FormikConfig<CountryEditionFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);
    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      confidence: parseInt(String(values.confidence), 10),
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    editor.fieldPatch({
      variables: {
        id: country.id,
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
  const handleSubmitField = (name: string, value: Option | string) => {
    if (!enableReferences) {
      let finalValue: unknown = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as Option).value;
      }
      countryValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: country.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };
  const initialValues: CountryEditionFormValues = {
    name: country.name,
    description: country.description ?? '',
    references: [],
    confidence: country.confidence,
    createdBy: convertCreatedBy(country) as Option,
    objectMarking: convertMarkings(country),
    x_opencti_workflow_id: convertStatus(t_i18n, country) as Option,
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={countryValidator}
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
        <Form style={{ margin: '20px 0 20px 0' }}>
          <AlertConfidenceForEntity entity={country} />
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
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Country"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          {country?.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Country"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
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
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              setFieldValue={setFieldValue}
              open={false}
              values={values.references}
              id={country.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default CountryEditionOverviewComponent;
