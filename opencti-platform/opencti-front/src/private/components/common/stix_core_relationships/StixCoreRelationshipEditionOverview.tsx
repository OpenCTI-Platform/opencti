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
import { MESSAGING$ } from 'src/relay/environment';
import { buildDate, formatDate } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import { SubscriptionAvatars, SubscriptionFocus } from '../../../../components/Subscription';
import KillChainPhasesField from '../form/KillChainPhasesField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import CreatedByField from '../form/CreatedByField';
import ConfidenceField from '../form/ConfidenceField';
import CommitMessage from '../form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertKillChainPhases, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../form/StatusField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useIsEnforceReference, useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { StixCoreRelationshipEditionOverviewQuery } from './__generated__/StixCoreRelationshipEditionOverviewQuery.graphql';
import {
  StixCoreRelationshipEditionOverview_stixCoreRelationship$data,
  StixCoreRelationshipEditionOverview_stixCoreRelationship$key,
} from './__generated__/StixCoreRelationshipEditionOverview_stixCoreRelationship.graphql';
import { Option } from '../form/ReferenceField';
import type { Theme } from '../../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
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

const StixCoreRelationshipEditionOverviewFragment = graphql`
  fragment StixCoreRelationshipEditionOverview_stixCoreRelationship on StixCoreRelationship {
    id
    confidence
    start_time
    stop_time
    description
    relationship_type
    is_inferred
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
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
    editContext {
      name
      focusOn
    }
  }
`;

const stixCoreRelationshipMutationFieldPatch = graphql`
  mutation StixCoreRelationshipEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixCoreRelationshipEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...StixCoreRelationshipEditionOverview_stixCoreRelationship
        ...StixCoreRelationshipOverview_stixCoreRelationship
      }
    }
  }
`;

export const stixCoreRelationshipEditionFocus = graphql`
  mutation StixCoreRelationshipEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixCoreRelationshipEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixCoreRelationshipMutationRelationAdd = graphql`
  mutation StixCoreRelationshipEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    stixCoreRelationshipEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixCoreRelationshipEditionOverview_stixCoreRelationship
        }
      }
    }
  }
`;

const stixCoreRelationshipMutationRelationDelete = graphql`
  mutation StixCoreRelationshipEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...StixCoreRelationshipEditionOverview_stixCoreRelationship
      }
    }
  }
`;

export const stixCoreRelationshipEditionOverviewQuery = graphql`
  query StixCoreRelationshipEditionOverviewQuery($id: String!) {
    stixCoreRelationship(id: $id) {
      ...StixCoreRelationshipEditionOverview_stixCoreRelationship
    }
  }
`;

interface StixCoreRelationshipEditionOverviewProps {
  handleClose: () => void;
  handleDelete: () => void;
  queryRef: PreloadedQuery<StixCoreRelationshipEditionOverviewQuery>;
  stixCoreRelationship: StixCoreRelationshipEditionOverview_stixCoreRelationship$data;
  noStoreUpdate: boolean;
}

interface StixCoreRelationshipAddInput {
  confidence: number | null;
  start_time: null | Date;
  stop_time: null | Date;
  description: string | null;
  killChainPhases: Option[];
  x_opencti_workflow_id: Option;
  createdBy: Option | undefined;
  objectMarking: Option[];
  message?: string;
  references?: Option[];
}

const StixCoreRelationshipEditionOverviewComponent: FunctionComponent<
Omit<StixCoreRelationshipEditionOverviewProps, 'queryRef'>
> = ({ handleClose, handleDelete, stixCoreRelationship, noStoreUpdate }) => {
  const stixCoreRelationshipType = 'stix-core-relationship';

  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const enableReferences = useIsEnforceReference(stixCoreRelationshipType);

  const handleToastUpdate = () => {
    MESSAGING$.notifySuccess(t_i18n('Relationship successfully edited'));
  };

  const { editContext } = stixCoreRelationship;

  const basicShape = {
    confidence: Yup.number().nullable(),
    start_time: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
    stop_time: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .min(Yup.ref('start_time'), "The end date can't be before start date")
      .nullable(),
    description: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const stixCoreRelationshipValidator = useSchemaEditionValidation(
    'stix-core-relationship',
    basicShape,
  );

  const queries = {
    fieldPatch: stixCoreRelationshipMutationFieldPatch,
    relationAdd: stixCoreRelationshipMutationRelationAdd,
    relationDelete: stixCoreRelationshipMutationRelationDelete,
    editionFocus: stixCoreRelationshipEditionFocus,
  };
  const editor = useFormEditor(
    stixCoreRelationship as GenericData,
    enableReferences,
    queries,
    stixCoreRelationshipValidator,
  );

  // necessary for stop_time because the validator includes a reference to another value (start_time)
  const handleSubmitFieldStopTime = (name: string, value: string) => {
    if (!enableReferences) {
      editor.fieldPatch({
        variables: {
          id: stixCoreRelationship.id,
          input: { key: name, value: value ?? '' },
        },
        onCompleted: handleToastUpdate,
      });
    }
  };

  const onSubmit: FormikConfig<StixCoreRelationshipAddInput>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      confidence: parseInt(String(values.confidence), 10),
      start_time: formatDate(values.start_time),
      stop_time: formatDate(values.stop_time),
      killChainPhases: (values.killChainPhases ?? []).map(({ value }) => value),
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      createdBy: values.createdBy?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));

    editor.fieldPatch({
      variables: {
        id: stixCoreRelationship.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleToastUpdate();
        handleClose();
      },
    });
  };
  const initialValues: StixCoreRelationshipAddInput = {
    confidence: stixCoreRelationship.confidence ?? null,
    start_time: buildDate(stixCoreRelationship.start_time),
    stop_time: buildDate(stixCoreRelationship.stop_time),
    description: stixCoreRelationship.description ?? '',
    killChainPhases: convertKillChainPhases(stixCoreRelationship),
    x_opencti_workflow_id: convertStatus(t_i18n, stixCoreRelationship) as Option,
    createdBy: convertCreatedBy(stixCoreRelationship) as Option,
    objectMarking: convertMarkings(stixCoreRelationship),
    references: [],
  };
  return (
    <>
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
          {t_i18n('Update a relationship')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={stixCoreRelationshipValidator}
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
              <AlertConfidenceForEntity entity={stixCoreRelationship} />
              <ConfidenceField
                variant="edit"
                onFocus={editor.changeFocus}
                onSubmit={editor.changeField}
                containerStyle={{ width: '100%' }}
                editContext={editContext}
                entityType={stixCoreRelationshipType}
              />
              <Field
                component={DateTimePickerField}
                name="start_time"
                onFocus={editor.changeFocus}
                onSubmit={editor.changeField}
                textFieldProps={{
                  label: t_i18n('Start time'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                  helperText: (
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="start_time"
                    />
                  ),
                }}
              />
              <Field
                component={DateTimePickerField}
                name="stop_time"
                onFocus={editor.changeFocus}
                onSubmit={handleSubmitFieldStopTime}
                textFieldProps={{
                  label: t_i18n('Stop time'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                  helperText: (
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="stop_time"
                    />
                  ),
                }}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t_i18n('Description')}
                fullWidth={true}
                multiline={true}
                rows={4}
                style={{ marginTop: 20 }}
                onFocus={editor.changeFocus}
                onSubmit={editor.changeField}
                helperText={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="description"
                  />
                }
              />
              <KillChainPhasesField
                name="killChainPhases"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
                helpertext={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="killChainPhases"
                  />
                }
                onChange={editor.changeKillChainPhases}
              />
              {stixCoreRelationship.workflowEnabled && (
                <StatusField
                  name="x_opencti_workflow_id"
                  type={stixCoreRelationshipType}
                  onFocus={editor.changeFocus}
                  onChange={editor.changeField}
                  setFieldValue={setFieldValue}
                  style={{ marginTop: 20 }}
                  helpertext={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="x_opencti_workflow_id"
                    />
                  }
                />
              )}
              <CreatedByField
                name="createdBy"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
                helpertext={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="createdBy"
                  />
                }
                onChange={editor.changeCreated}
              />
              <ObjectMarkingField
                name="objectMarking"
                style={fieldSpacingContainerStyle}
                helpertext={
                  <SubscriptionFocus
                    context={editContext}
                    fieldname="objectMarking"
                  />
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
                  id={stixCoreRelationship.id}
                  noStoreUpdate={noStoreUpdate}
                />
              )}
            </Form>
          )}
        </Formik>
        {typeof handleDelete === 'function' && (
          <Button
            variant="contained"
            onClick={() => {
              handleDelete();
            }}
            classes={{ root: classes.button }}
          >
            {t_i18n('Delete')}
          </Button>
        )}
      </div>
    </>
  );
};

const StixCoreRelationshipEditionOverview: FunctionComponent<
Omit<StixCoreRelationshipEditionOverviewProps, 'stixCoreRelationship'>
> = (props) => {
  const queryData = usePreloadedQuery(
    stixCoreRelationshipEditionOverviewQuery,
    props.queryRef,
  );
  if (queryData.stixCoreRelationship === null) {
    return <ErrorNotFound />;
  }
  // eslint-disable-next-line max-len
  const stixCoreRelationship = useFragment<StixCoreRelationshipEditionOverview_stixCoreRelationship$key>(
    StixCoreRelationshipEditionOverviewFragment,
    queryData.stixCoreRelationship,
  );
  if (!stixCoreRelationship) {
    return null;
  }
  return (
    <StixCoreRelationshipEditionOverviewComponent
      {...props}
      stixCoreRelationship={stixCoreRelationship}
    />
  );
};

export default StixCoreRelationshipEditionOverview;
