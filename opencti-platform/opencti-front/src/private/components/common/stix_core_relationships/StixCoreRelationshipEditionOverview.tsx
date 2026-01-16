import Button from '@common/button/Button';
import { CoverageInformationFieldEdit } from '@components/common/form/CoverageInformationField';
import { Stack } from '@mui/material';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import * as Yup from 'yup';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { SubscriptionFocus } from '../../../../components/Subscription';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import { adaptFieldValue } from '../../../../utils/String';
import { buildDate, formatDate } from '../../../../utils/Time';
import { convertCreatedBy, convertKillChainPhases, convertMarkings, convertStatus } from '../../../../utils/edition';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useIsEnforceReference, useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import CommitMessage from '../form/CommitMessage';
import ConfidenceField from '../form/ConfidenceField';
import CreatedByField from '../form/CreatedByField';
import KillChainPhasesField from '../form/KillChainPhasesField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import StatusField from '../form/StatusField';
import { StixCoreRelationshipEditionOverviewQuery } from './__generated__/StixCoreRelationshipEditionOverviewQuery.graphql';
import {
  StixCoreRelationshipEditionOverview_stixCoreRelationship$data,
  StixCoreRelationshipEditionOverview_stixCoreRelationship$key,
} from './__generated__/StixCoreRelationshipEditionOverview_stixCoreRelationship.graphql';

const StixCoreRelationshipEditionOverviewFragment = graphql`
  fragment StixCoreRelationshipEditionOverview_stixCoreRelationship on StixCoreRelationship {
    id
    confidence
    entity_type
    start_time
    stop_time
    description
    relationship_type
    is_inferred
    coverage_information {
      coverage_name
      coverage_score
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

export interface StixCoreRelationshipEditionOverviewProps {
  handleClose: () => void;
  handleDelete?: () => void;
  queryRef: PreloadedQuery<StixCoreRelationshipEditionOverviewQuery>;
  stixCoreRelationship: StixCoreRelationshipEditionOverview_stixCoreRelationship$data;
  noStoreUpdate: boolean;
  isCoverage?: boolean;
}

interface StixCoreRelationshipAddInput {
  confidence: number | null;
  start_time: null | Date;
  stop_time: null | Date;
  description: string | null;
  killChainPhases: FieldOption[];
  x_opencti_workflow_id: FieldOption;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  message?: string;
  references?: FieldOption[];
  coverage_information?: readonly {
    readonly coverage_name: string;
    readonly coverage_score: number;
  }[] | undefined;
}

const StixCoreRelationshipEditionOverviewComponent: FunctionComponent<
  Omit<StixCoreRelationshipEditionOverviewProps, 'queryRef'>
> = ({ handleClose, handleDelete, stixCoreRelationship, noStoreUpdate, isCoverage = false }) => {
  const stixCoreRelationshipType = 'stix-core-relationship';

  const { t_i18n } = useFormatter();
  const enableReferences = useIsEnforceReference(stixCoreRelationshipType);

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
    x_opencti_workflow_id: convertStatus(t_i18n, stixCoreRelationship) as FieldOption,
    createdBy: convertCreatedBy(stixCoreRelationship) as FieldOption,
    objectMarking: convertMarkings(stixCoreRelationship),
    references: [],
    ...(isCoverage ? { coverage_information: stixCoreRelationship.coverage_information || [] } : {}),
  };
  return (
    <Stack>
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
          <Form>
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
                style: { marginTop: 40 },
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
              helperText={(
                <SubscriptionFocus
                  context={editContext}
                  fieldName="description"
                />
              )}
            />
            {isCoverage && (
              <CoverageInformationFieldEdit
                id={stixCoreRelationship.id}
                name="coverage_information"
                mode="relation"
                values={values.coverage_information ?? []}
                containerStyle={fieldSpacingContainerStyle}
              />
            )}
            <KillChainPhasesField
              name="killChainPhases"
              style={fieldSpacingContainerStyle}
              helpertext={(
                <SubscriptionFocus
                  context={editContext}
                  fieldName="killChainPhases"
                />
              )}
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
                helpertext={(
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="x_opencti_workflow_id"
                  />
                )}
              />
            )}
            <CreatedByField
              name="createdBy"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              helpertext={(
                <SubscriptionFocus
                  context={editContext}
                  fieldName="createdBy"
                />
              )}
              onChange={editor.changeCreated}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={fieldSpacingContainerStyle}
              helpertext={(
                <SubscriptionFocus
                  context={editContext}
                  fieldname="objectMarking"
                />
              )}
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
        <Stack direction="row" alignSelf="flex-end" sx={{ mt: 3 }}>
          <Button
            intent="destructive"
            onClick={handleDelete}
            variant="secondary"
          >
            {t_i18n('Delete')}
          </Button>
        </Stack>
      )}
    </Stack>
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
