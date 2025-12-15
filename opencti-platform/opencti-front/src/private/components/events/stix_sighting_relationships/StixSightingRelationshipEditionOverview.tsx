import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { buildDate, formatDate } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionAvatars, SubscriptionFocus } from '../../../../components/Subscription';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import CreatedByField from '../../common/form/CreatedByField';
import ConfidenceField from '../../common/form/ConfidenceField';
import SwitchField from '../../../../components/fields/SwitchField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useIsEnforceReference, useDynamicSchemaEditionValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { adaptFieldValue } from '../../../../utils/String';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import {
  StixSightingRelationshipEditionOverview_stixSightingRelationship$data,
  StixSightingRelationshipEditionOverview_stixSightingRelationship$key,
} from './__generated__/StixSightingRelationshipEditionOverview_stixSightingRelationship.graphql';
import CommitMessage from '../../common/form/CommitMessage';
import type { Theme } from '../../../../components/Theme';
import { StixSightingRelationshipEditionOverviewQuery } from './__generated__/StixSightingRelationshipEditionOverviewQuery.graphql';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
}));

const StixSightingRelationshipEditionOverviewFragment = graphql`
  fragment StixSightingRelationshipEditionOverview_stixSightingRelationship on StixSightingRelationship {
    id
    attribute_count
    x_opencti_negative
    confidence
    entity_type
    first_seen
    last_seen
    description
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
    editContext {
      name
      focusOn
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

const stixSightingRelationshipMutationFieldPatch = graphql`
  mutation StixSightingRelationshipEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixSightingRelationshipEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...StixSightingRelationshipEditionOverview_stixSightingRelationship
      }
    }
  }
`;

export const stixSightingRelationshipEditionFocus = graphql`
  mutation StixSightingRelationshipEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixSightingRelationshipEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixSightingRelationshipMutationRelationAdd = graphql`
  mutation StixSightingRelationshipEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    stixSightingRelationshipEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixSightingRelationshipEditionOverview_stixSightingRelationship
        }
      }
    }
  }
`;

const stixSightingRelationshipMutationRelationDelete = graphql`
  mutation StixSightingRelationshipEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixSightingRelationshipEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...StixSightingRelationshipEditionOverview_stixSightingRelationship
      }
    }
  }
`;

export const stixSightingRelationshipEditionOverviewQuery = graphql`
  query StixSightingRelationshipEditionOverviewQuery($id: String!) {
    stixSightingRelationship(id: $id) {
      ...StixSightingRelationshipEditionOverview_stixSightingRelationship
    }
  }
`;

const STIX_SIGHTING_TYPE = 'stix-sighting-relationship';

interface StixSightingRelationshipEditionOverviewProps {
  handleClose: () => void;
  handleDelete: () => void;
  queryRef: PreloadedQuery<StixSightingRelationshipEditionOverviewQuery>;
  stixSightingRelationship: StixSightingRelationshipEditionOverview_stixSightingRelationship$data;
  inferred: boolean;
  noStoreUpdate: boolean;
}

interface StixSightingRelationshipAddInput {
  attribute_count: number;
  confidence: number | null;
  first_seen: null | Date;
  last_seen: null | Date;
  description: string | null;
  x_opencti_negative: boolean | null;
  x_opencti_workflow_id: FieldOption;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  message?: string;
  references?: FieldOption[];
}

const StixSightingRelationshipEditionOverviewComponent: FunctionComponent<Omit<StixSightingRelationshipEditionOverviewProps, 'queryRef'>> = ({
  handleClose,
  stixSightingRelationship,
  inferred,
  noStoreUpdate,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const enableReferences = useIsEnforceReference(STIX_SIGHTING_TYPE);

  const { editContext } = stixSightingRelationship;

  const { mandatoryAttributes } = useIsMandatoryAttribute(STIX_SIGHTING_TYPE);
  const basicShape = yupShapeConditionalRequired({
    attribute_count: Yup.number()
      .typeError(t_i18n('The value must be a number'))
      .integer(t_i18n('The value must be a number')),
    confidence: Yup.number()
      .typeError(t_i18n('The value must be a number'))
      .integer(t_i18n('The value must be a number')),
    first_seen: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
    last_seen: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
    description: Yup.string().nullable(),
    x_opencti_negative: Yup.boolean(),
    x_opencti_workflow_id: Yup.object(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);
  const stixSightingRelationshipValidator = useDynamicSchemaEditionValidation(mandatoryAttributes, basicShape);

  const queries = {
    fieldPatch: stixSightingRelationshipMutationFieldPatch,
    relationAdd: stixSightingRelationshipMutationRelationAdd,
    relationDelete: stixSightingRelationshipMutationRelationDelete,
    editionFocus: stixSightingRelationshipEditionFocus,
  };
  const editor = useFormEditor(stixSightingRelationship as GenericData, enableReferences, queries, stixSightingRelationshipValidator);

  const onSubmit: FormikConfig<StixSightingRelationshipAddInput>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      confidence: parseInt(String(values.confidence), 10),
      first_seen: formatDate(values.first_seen),
      last_seen: formatDate(values.last_seen),
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      createdBy: values.createdBy?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));

    editor.fieldPatch({
      variables: {
        id: stixSightingRelationship.id,
        input: inputValues,
        commitMessage: commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };
  const initialValues: StixSightingRelationshipAddInput = {
    attribute_count: stixSightingRelationship.attribute_count,
    confidence: stixSightingRelationship.confidence ?? null,
    first_seen: buildDate(stixSightingRelationship.first_seen),
    last_seen: buildDate(stixSightingRelationship.last_seen),
    description: stixSightingRelationship.description ?? null,
    x_opencti_negative: stixSightingRelationship.x_opencti_negative,
    x_opencti_workflow_id: convertStatus(t_i18n, stixSightingRelationship) as FieldOption,
    createdBy: convertCreatedBy(stixSightingRelationship) as FieldOption,
    objectMarking: convertMarkings(stixSightingRelationship),
    references: [],
  };

  return (
    <>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t_i18n('Update a sighting')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={stixSightingRelationshipValidator}
          validateOnChange={true}
          validateOnBlur={true}
          onSubmit={onSubmit}
        >
          {({ submitForm, isSubmitting, setFieldValue, values, isValid, dirty }) => (
            <Form>
              <AlertConfidenceForEntity entity={stixSightingRelationship} />
              <Field
                component={TextField}
                variant="standard"
                name="attribute_count"
                label={t_i18n('Count')}
                required={(mandatoryAttributes.includes('attribute_count'))}
                fullWidth={true}
                onFocus={editor.changeFocus}
                onSubmit={editor.changeField}
                helperText={
                  <SubscriptionFocus context={editContext} fieldName="attribute_count" />
                }
                disabled={inferred}
              />
              <ConfidenceField
                variant="edit"
                onFocus={editor.changeFocus}
                onSubmit={editor.changeField}
                editContext={editContext}
                containerStyle={fieldSpacingContainerStyle}
                disabled={inferred}
                entityType={STIX_SIGHTING_TYPE}
              />
              <Field
                component={DateTimePickerField}
                name="first_seen"
                onFocus={editor.changeFocus}
                onChange={editor.changeField}
                textFieldProps={{
                  label: t_i18n('First seen'),
                  required: (mandatoryAttributes.includes('first_seen')),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                  helperText: (
                    <SubscriptionFocus context={editContext} fieldName="first_seen" />
                  ),
                }}
                disabled={inferred}
              />
              <Field
                component={DateTimePickerField}
                name="last_seen"
                onFocus={editor.changeFocus}
                onChange={editor.changeField}
                textFieldProps={{
                  label: t_i18n('Last seen'),
                  required: (mandatoryAttributes.includes('last_seen')),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                  helperText: (
                    <SubscriptionFocus context={editContext} fieldName="last_seen" />
                  ),
                }}
                disabled={inferred}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t_i18n('Description')}
                required={(mandatoryAttributes.includes('description'))}
                fullWidth={true}
                multiline={true}
                rows={4}
                style={{ marginTop: 20 }}
                onFocus={editor.changeFocus}
                onSubmit={editor.changeField}
                helperText={
                  <SubscriptionFocus context={editContext} fieldName="description" />
                }
                disabled={inferred}
              />
              {stixSightingRelationship.workflowEnabled && (
                <StatusField
                  name="x_opencti_workflow_id"
                  type="stix-sighting-relationship"
                  onFocus={editor.changeFocus}
                  onChange={editor.changeField}
                  setFieldValue={setFieldValue}
                  style={{ marginTop: 20 }}
                  helpertext={
                    <SubscriptionFocus context={editContext} fieldName="x_opencti_workflow_id" />
                  }
                />
              )}
              <CreatedByField
                name="createdBy"
                required={(mandatoryAttributes.includes('createdBy'))}
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
                helpertext={
                  <SubscriptionFocus context={editContext} fieldName="createdBy" />
                }
                disabled={inferred}
                onChange={editor.changeCreated}
              />
              <ObjectMarkingField
                name="objectMarking"
                required={(mandatoryAttributes.includes('objectMarking'))}
                style={fieldSpacingContainerStyle}
                helpertext={
                  <SubscriptionFocus context={editContext} fieldname="objectMarking" />
                }
                disabled={inferred}
                setFieldValue={setFieldValue}
                onChange={editor.changeMarking}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="x_opencti_negative"
                label={t_i18n('False positive')}
                containerstyle={{ marginTop: 20 }}
                onChange={editor.changeField}
                helperText={
                  <SubscriptionFocus context={editContext} fieldName="x_opencti_negative" />
                }
                disabled={inferred}
              />
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                width: '100%',
              }}
              >
                {enableReferences && (
                  <CommitMessage
                    submitForm={submitForm}
                    disabled={isSubmitting || !isValid || !dirty}
                    setFieldValue={setFieldValue}
                    open={false}
                    values={values.references}
                    id={stixSightingRelationship.id}
                    noStoreUpdate={noStoreUpdate}
                  />
                )}
              </div>
            </Form>
          )}
        </Formik>
      </div>
    </>
  );
};

const StixSightingRelationshipEditionOverview: FunctionComponent<Omit<StixSightingRelationshipEditionOverviewProps, 'stixSightingRelationship'>> = (
  props,
) => {
  const queryData = usePreloadedQuery(stixSightingRelationshipEditionOverviewQuery, props.queryRef);
  if (queryData.stixSightingRelationship === null) {
    return <ErrorNotFound />;
  }
  // eslint-disable-next-line max-len
  const stixSightingRelationship = useFragment<StixSightingRelationshipEditionOverview_stixSightingRelationship$key>(StixSightingRelationshipEditionOverviewFragment, queryData.stixSightingRelationship);
  if (!stixSightingRelationship) {
    return null;
  }
  return <StixSightingRelationshipEditionOverviewComponent {...props} stixSightingRelationship={stixSightingRelationship} />;
};

export default StixSightingRelationshipEditionOverview;
