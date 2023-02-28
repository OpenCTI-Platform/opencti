import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import * as R from 'ramda';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { adaptFieldValue } from '../../../../utils/String';
import { Option } from '../../common/form/ReferenceField';
import { useFormatter } from '../../../../components/i18n';
import { RegionEditionOverview_region$key } from './__generated__/RegionEditionOverview_region.graphql';
import CommitMessage from '../../common/form/CommitMessage';
import { useYupSchemaBuilder } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';

const regionMutationFieldPatch = graphql`
  mutation RegionEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    regionEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...RegionEditionOverview_region
        ...Region_region
      }
    }
  }
`;

export const regionEditionOverviewFocus = graphql`
  mutation RegionEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    regionEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const regionMutationRelationAdd = graphql`
  mutation RegionEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    regionEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...RegionEditionOverview_region
        }
      }
    }
  }
`;

const regionMutationRelationDelete = graphql`
  mutation RegionEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    regionEdit(id: $id) {
      relationDelete(
        toId: $toId,
        relationship_type: $relationship_type
      ) {
        ...RegionEditionOverview_region
      }
    }
  }
`;

const regionEditionOverviewFragment = graphql`
  fragment RegionEditionOverview_region on Region {
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

interface RegionEdititionOverviewProps {
  regionRef: RegionEditionOverview_region$key,
  context: readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[] | null
  enableReferences?: boolean
  handleClose: () => void
}

interface RegionEditionFormValues {
  name: string
  description: string | null
  createdBy: Option | undefined
  objectMarking: Option[]
  x_opencti_workflow_id: Option
  message?: string,
  references?: Option[]
}

const RegionEditionOverviewComponent: FunctionComponent<RegionEdititionOverviewProps> = ({
  regionRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t } = useFormatter();
  const region = useFragment(regionEditionOverviewFragment, regionRef);

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };

  const regionValidator = useYupSchemaBuilder('Region', basicShape);

  const queries = {
    fieldPatch: regionMutationFieldPatch,
    relationAdd: regionMutationRelationAdd,
    relationDelete: regionMutationRelationDelete,
    editionFocus: regionEditionOverviewFocus,
  };
  const editor = useFormEditor(region, enableReferences, queries, regionValidator);

  const onSubmit: FormikConfig<RegionEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
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
        id: region.id,
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
      regionValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: region.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    name: region.name,
    description: region.description,
    createdBy: convertCreatedBy(region),
    objectMarking: convertMarkings(region),
    x_opencti_workflow_id: convertStatus(t, region) as Option,
    references: [],
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={regionValidator}
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
          {region.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Region"
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
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              setFieldValue={setFieldValue}
              open={false}
              values={values.references}
              id={region.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default RegionEditionOverviewComponent;
