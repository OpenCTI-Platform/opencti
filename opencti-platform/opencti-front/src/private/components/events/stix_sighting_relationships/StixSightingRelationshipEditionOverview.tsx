import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Button from '@mui/material/Button';
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
import SwitchField from '../../../../components/SwitchField';
import MarkDownField from '../../../../components/MarkDownField';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useIsEnforceReference, useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { adaptFieldValue } from '../../../../utils/String';
import { Option } from '../../common/form/ReferenceField';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import {
  StixSightingRelationshipEditionOverview_stixSightingRelationship$data,
  StixSightingRelationshipEditionOverview_stixSightingRelationship$key,
} from './__generated__/StixSightingRelationshipEditionOverview_stixSightingRelationship.graphql';
import CommitMessage from '../../common/form/CommitMessage';
import { Theme } from '../../../../components/Theme';
import {
  StixSightingRelationshipEditionOverviewQuery,
} from './__generated__/StixSightingRelationshipEditionOverviewQuery.graphql';

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
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  button: {
    float: 'right',
    backgroundColor: theme.palette.error.main,
    borderColor: theme.palette.error.main,
    color: theme.palette.common.white,
    '&:hover': {
      backgroundColor: theme.palette.error.dark,
      borderColor: theme.palette.error.dark,
    },
  },
}));

const StixSightingRelationshipEditionOverviewFragment = graphql`
  fragment StixSightingRelationshipEditionOverview_stixSightingRelationship on StixSightingRelationship {
    id
    attribute_count
    x_opencti_negative
    confidence
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

interface StixSightingRelationshipEditionOverviewProps {
  handleClose: () => void;
  handleDelete: () => void;
  queryRef: PreloadedQuery<StixSightingRelationshipEditionOverviewQuery>;
  stixSightingRelationship: StixSightingRelationshipEditionOverview_stixSightingRelationship$data;
  inferred: boolean
  noStoreUpdate: boolean
}

interface StixSightingRelationshipAddInput {
  attribute_count: number;
  confidence: number | null;
  first_seen: null | Date;
  last_seen: null | Date;
  description: string | null,
  x_opencti_negative: boolean | null,
  x_opencti_workflow_id: Option;
  createdBy: Option | undefined;
  objectMarking: Option[];
  message?: string
  references?: Option[]
}

const StixSightingRelationshipEditionOverviewComponent: FunctionComponent<Omit<StixSightingRelationshipEditionOverviewProps, 'queryRef'>> = ({
  handleClose,
  handleDelete,
  stixSightingRelationship,
  inferred,
  noStoreUpdate,
}) => {
  const stixSightingRelationshipType = 'stix-sighting-relationship';

  const { t } = useFormatter();
  const classes = useStyles();
  const enableReferences = useIsEnforceReference(stixSightingRelationshipType);

  const { editContext } = stixSightingRelationship;

  const basicShape = {
    attribute_count: Yup.number()
      .typeError(t('The value must be a number'))
      .integer(t('The value must be a number'))
      .required(t('This field is required')),
    confidence: Yup.number()
      .typeError(t('The value must be a number'))
      .integer(t('The value must be a number'))
      .required(t('This field is required')),
    first_seen: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t('This field is required')),
    last_seen: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t('This field is required')),
    description: Yup.string().nullable(),
    x_opencti_negative: Yup.boolean(),
    x_opencti_workflow_id: Yup.object(),
  };
  const stixSightingRelationshipValidator = useSchemaEditionValidation('stix-sighting-relationship', basicShape);

  const queries = {
    fieldPatch: stixSightingRelationshipMutationFieldPatch,
    relationAdd: stixSightingRelationshipMutationRelationAdd,
    relationDelete: stixSightingRelationshipMutationRelationDelete,
    editionFocus: stixSightingRelationshipEditionFocus,
  };
  const editor = useFormEditor(stixSightingRelationship, enableReferences, queries, stixSightingRelationshipValidator);

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
    confidence: stixSightingRelationship.confidence,
    first_seen: buildDate(stixSightingRelationship.first_seen),
    last_seen: buildDate(stixSightingRelationship.last_seen),
    description: stixSightingRelationship.description,
    x_opencti_negative: stixSightingRelationship.x_opencti_negative,
    x_opencti_workflow_id: convertStatus(t, stixSightingRelationship) as Option,
    createdBy: convertCreatedBy(stixSightingRelationship) as Option,
    objectMarking: convertMarkings(stixSightingRelationship),
    references: [],
  };

  return (
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Update a sighting')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={stixSightingRelationshipValidator}
          onSubmit={onSubmit}
        >
          {({ submitForm, isSubmitting, setFieldValue, values, isValid, dirty }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="attribute_count"
                label={t('Count')}
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
                entityType={stixSightingRelationshipType}
              />
              <Field
                component={DateTimePickerField}
                name="first_seen"
                onFocus={editor.changeFocus}
                onChange={editor.changeField}
                TextFieldProps={{
                  label: t('First seen'),
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
                TextFieldProps={{
                  label: t('Last seen'),
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
                component={MarkDownField}
                name="description"
                label={t('Description')}
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
                style={fieldSpacingContainerStyle}
                helpertext={
                  <SubscriptionFocus context={editContext} fieldname="objectMarking" />
                }
                disabled={inferred}
                onChange={editor.changeMarking}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="x_opencti_negative"
                label={t('False positive')}
                containerstyle={{ marginTop: 20 }}
                onChange={editor.changeField}
                helperText={
                  <SubscriptionFocus context={editContext} fieldName="x_opencti_negative" />
                }
                disabled={inferred}
              />
              {enableReferences && (
                <CommitMessage
                  submitForm={submitForm}
                  disabled={isSubmitting || !isValid || !dirty}
                  setFieldValue={setFieldValue}
                  open={false}
                  values={values.references}
                  id={stixSightingRelationship.id}
                  noStoreUpdate={noStoreUpdate} />
              )}
            </Form>
          )}
        </Formik>
        {typeof handleDelete === 'function' && (
          <Button
            variant="contained"
            onClick={() => handleDelete()}
            classes={{ root: classes.button }}
            disabled={inferred}
          >
            {t('Delete')}
          </Button>
        )}
        <div className="clearfix" />
      </div>
    </div>
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
  return <StixSightingRelationshipEditionOverviewComponent {...props} stixSightingRelationship={stixSightingRelationship} />;
};

export default StixSightingRelationshipEditionOverview;
