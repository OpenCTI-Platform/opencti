import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { IncidentsLinesQuery$variables } from '@components/events/incidents/__generated__/IncidentsLinesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { insertNode } from '../../../../utils/store';
import OpenVocabField from '../../common/form/OpenVocabField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { isEmptyField } from '../../../../utils/utils';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import type { Theme } from '../../../../components/Theme';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const IncidentMutation = graphql`
  mutation IncidentCreationMutation($input: IncidentAddInput!) {
    incidentAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
      description
      entity_type
      parent_types
      ...IncidentLine_node
    }
  }
`;

interface IncidentAddInput {
  name: string;
  description: string;
  confidence: number | undefined;
  incident_type: string;
  severity: string;
  source: string;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  objectAssignee: FieldOption[];
  objectParticipant: FieldOption[];
  externalReferences: FieldOption[];
  file: File | undefined;
}

interface IncidentCreationProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: FieldOption;
  defaultMarkingDefinitions?: FieldOption[];
  defaultConfidence?: number;
  inputValue?: string;
}

const INCIDENT_TYPE = 'Incident';

export const IncidentCreationForm: FunctionComponent<IncidentCreationProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  inputValue,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(
    IncidentMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Incident')} ${t_i18n('successfully created')}` },
  );
  const { mandatoryAttributes } = useIsMandatoryAttribute(INCIDENT_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    confidence: Yup.number().nullable(),
    incident_type: Yup.string().nullable(),
    severity: Yup.string().nullable(),
    source: Yup.string().nullable(),
    description: Yup.string().nullable(),
  }, mandatoryAttributes);
  const incidentValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
  );
  const onSubmit: FormikConfig<IncidentAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const cleanedValues = isEmptyField(values.severity)
      ? R.dissoc('severity', values)
      : values;
    const input = {
      ...cleanedValues,
      confidence: parseInt(String(cleanedValues.confidence), 10),
      createdBy: cleanedValues.createdBy?.value,
      objectMarking: cleanedValues.objectMarking.map((v) => v.value),
      objectAssignee: cleanedValues.objectAssignee.map(({ value }) => value),
      objectParticipant: cleanedValues.objectParticipant.map(
        ({ value }) => value,
      ),
      objectLabel: cleanedValues.objectLabel.map(({ value }) => value),
      externalReferences: cleanedValues.externalReferences.map(
        ({ value }) => value,
      ),
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'incidentAdd');
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };
  const initialValues = useDefaultValues<IncidentAddInput>(INCIDENT_TYPE, {
    name: inputValue ?? '',
    confidence: defaultConfidence,
    incident_type: '',
    severity: '',
    source: '',
    description: '',
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectAssignee: [],
    objectParticipant: [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
  });
  return (
    <Formik<IncidentAddInput>
      initialValues={initialValues}
      validationSchema={incidentValidator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            detectDuplicate={['Incident']}
          />
          <ConfidenceField
            entityType="Incident"
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t_i18n('Incident type')}
            type="incident-type-ov"
            name="incident_type"
            required={(mandatoryAttributes.includes('incident_type'))}
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
            onChange={setFieldValue}
          />
          <OpenVocabField
            label={t_i18n('Severity')}
            type="incident-severity-ov"
            name="severity"
            required={(mandatoryAttributes.includes('severity'))}
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
            onChange={setFieldValue}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={TextField}
            variant="standard"
            name="source"
            label={t_i18n('Source')}
            required={(mandatoryAttributes.includes('source'))}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
          />
          <ObjectAssigneeField
            name="objectAssignee"
            required={(mandatoryAttributes.includes('objectAssignee'))}
            style={fieldSpacingContainerStyle}
          />
          <ObjectParticipantField
            name="objectParticipant"
            required={(mandatoryAttributes.includes('objectParticipant'))}
            style={fieldSpacingContainerStyle}
          />
          <CreatedByField
            name="createdBy"
            required={(mandatoryAttributes.includes('createdBy'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            required={(mandatoryAttributes.includes('objectLabel'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={(mandatoryAttributes.includes('objectMarking'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ExternalReferencesField
            name="externalReferences"
            required={(mandatoryAttributes.includes('externalReferences'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <CustomFileUploader setFieldValue={setFieldValue} />
          <div className={classes.buttons}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

const IncidentCreation = ({
  paginationOptions,
}: {
  paginationOptions: IncidentsLinesQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_incidents', paginationOptions, 'incidentAdd');
  const CreateIncidentControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Incident" {...props} />
  );
  return (
    <Drawer
      title={t_i18n('Create an incident')}
      controlledDial={CreateIncidentControlledDial}
    >
      {({ onClose }) => (
        <IncidentCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default IncidentCreation;
