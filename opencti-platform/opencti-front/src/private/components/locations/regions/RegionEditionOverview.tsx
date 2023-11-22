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
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { adaptFieldValue } from '../../../../utils/String';
import { Option } from '../../common/form/ReferenceField';
import { useFormatter } from '../../../../components/i18n';
import { RegionEditionOverview_region$key } from './__generated__/RegionEditionOverview_region.graphql';
import CommitMessage from '../../common/form/CommitMessage';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { GenericContext } from '../../common/model/GenericContextModel';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

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
    $input: StixRefRelationshipAddInput!
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
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
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

interface RegionEdititionOverviewProps {
  regionRef: RegionEditionOverview_region$key;
  context?: readonly (GenericContext | null)[] | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface RegionEditionFormValues {
  name: string;
  description: string | null;
  createdBy: Option | undefined;
  confidence: number | undefined | null;
  objectMarking: Option[];
  x_opencti_workflow_id: Option;
  message?: string;
  references?: Option[];
}

const REGION_TYPE = 'Region';

const RegionEditionOverviewComponent: FunctionComponent<
RegionEdititionOverviewProps
> = ({ regionRef, context, enableReferences = false, handleClose }) => {
  const { t_i18n } = useFormatter();
  const region = useFragment(regionEditionOverviewFragment, regionRef);
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    REGION_TYPE,
  );
  const basicShape = {
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const regionValidator = useSchemaEditionValidation(REGION_TYPE, basicShape);
  const queries = {
    fieldPatch: regionMutationFieldPatch,
    relationAdd: regionMutationRelationAdd,
    relationDelete: regionMutationRelationDelete,
    editionFocus: regionEditionOverviewFocus,
  };
  const editor = useFormEditor(
    region as GenericData,
    enableReferences,
    queries,
    regionValidator,
  );
  const onSubmit: FormikConfig<RegionEditionFormValues>['onSubmit'] = (
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
        id: region.id,
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
    confidence: region.confidence,
    createdBy: convertCreatedBy(region),
    objectMarking: convertMarkings(region),
    x_opencti_workflow_id: convertStatus(t_i18n, region) as Option,
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
          <AlertConfidenceForEntity entity={region} />
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
            entityType="Region"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
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
              id={region.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default RegionEditionOverviewComponent;
