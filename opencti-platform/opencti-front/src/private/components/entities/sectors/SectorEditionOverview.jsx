import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const sectorMutationFieldPatch = graphql`
  mutation SectorEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    sectorEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...SectorEditionOverview_sector
        ...Sector_sector
      }
    }
  }
`;

export const sectorEditionOverviewFocus = graphql`
  mutation SectorEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    sectorEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const sectorMutationRelationAdd = graphql`
  mutation SectorEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    sectorEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...SectorEditionOverview_sector
        }
      }
    }
  }
`;

const sectorMutationRelationDelete = graphql`
  mutation SectorEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    sectorEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...SectorEditionOverview_sector
      }
    }
  }
`;

const SECTOR_TYPE = 'Sector';

const SectorEditionOverviewComponent = (props) => {
  const { sector, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    SECTOR_TYPE,
  );
  const basicShape = {
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const sectorValidator = useSchemaEditionValidation(SECTOR_TYPE, basicShape);

  const queries = {
    fieldPatch: sectorMutationFieldPatch,
    relationAdd: sectorMutationRelationAdd,
    relationDelete: sectorMutationRelationDelete,
    editionFocus: sectorEditionOverviewFocus,
  };
  const editor = useFormEditor(sector, enableReferences, queries, sectorValidator);

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('confidence', parseInt(values.confidence, 10)),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: sector.id,
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

  const handleSubmitField = (name, value) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      sectorValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: sector.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const createdBy = convertCreatedBy(sector);
  const objectMarking = convertMarkings(sector);
  const status = convertStatus(t_i18n, sector);
  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.assoc('references', []),
    R.pick([
      'name',
      'references',
      'description',
      'createdBy',
      'confidence',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(sector);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={sectorValidator}
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
          <AlertConfidenceForEntity entity={sector} />
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
            entityType="Sector"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          {sector.workflowEnabled && (
          <StatusField
            name="x_opencti_workflow_id"
            type="Sector"
            onFocus={editor.changeFocus}
            onChange={handleSubmitField}
            setFieldValue={setFieldValue}
            style={{ marginTop: 20 }}
            helpertext={
              <SubscriptionFocus context={context} fieldName="x_opencti_workflow_id" />
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
            id={sector.id}
          />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(SectorEditionOverviewComponent, {
  sector: graphql`
      fragment SectorEditionOverview_sector on Sector {
        id
        name
        description
        isSubSector
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
    `,
});
