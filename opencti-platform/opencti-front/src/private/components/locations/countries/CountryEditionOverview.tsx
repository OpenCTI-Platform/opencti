import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { CountryEditionOverview_country$key } from './__generated__/CountryEditionOverview_country.graphql';
import { Option } from '../../common/form/ReferenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { useYupSschemaBuilder } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';

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
    $input: StixMetaRelationshipAddInput!
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
      relationDelete(
        toId: $toId, 
        relationship_type: $relationship_type
      ) {
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
          definition_type
          definition
          x_opencti_order
          x_opencti_color
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
`;

interface CountryEditionOverviewProps {
  countryRef: CountryEditionOverview_country$key,
  context: readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[] | null
  enableReferences?: boolean
  handleClose: () => void
}

interface CountryEditionFormValues {
  name: string
  description: string | null
  createdBy: Option | undefined
  objectMarking: Option[]
  x_opencti_workflow_id: Option
  message?: string,
  references?: Option[]
}

const CountryEditionOverviewComponent: FunctionComponent<CountryEditionOverviewProps> = ({
  countryRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t } = useFormatter();
  const country = useFragment(countryEditionOverviewFragment, countryRef);

  const basicShape = {
    name: Yup.string().required(t('This field is required')),
    description: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const countryValidator = useYupSschemaBuilder('Country', basicShape);

  const queries = {
    fieldPatch: countryMutationFieldPatch,
    relationAdd: countryMutationRelationAdd,
    relationDelete: countryMutationRelationDelete,
    editionFocus: countryEditionOverviewFocus,
  };
  const editor = useFormEditor(country, enableReferences, queries, countryValidator);

  const onSubmit: FormikConfig<CountryEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: country.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
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
    description: country.description,
    createdBy: convertCreatedBy(country),
    objectMarking: convertMarkings(country),
    x_opencti_workflow_id: convertStatus(t, country) as Option,
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
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
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
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
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
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={editor.changeCreated}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus context={context} fieldname="objectMarking" />
              }
              onChange={editor.changeMarking}
            />
            {enableReferences && isValid && dirty && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
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
