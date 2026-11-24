import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { ProceduresLinesPaginationQuery$variables } from '@components/techniques/__generated__/ProceduresLinesPaginationQuery.graphql';
import { Stack } from '@mui/material';
import { Field, Form } from 'formik';
import Formik from '@components/common/custom_fields/CustomFieldsFormik';
import CustomFieldValuesCreation from '@components/common/custom_fields/CustomFieldValuesCreation';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import { FunctionComponent, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import { getCustomFieldValues } from '../../../../utils/customFields';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import ProgressBar from '../../../../components/ProgressBar';
import { handleErrorInForm } from '../../../../relay/environment';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import useMarkdownCreationFilesInput from '../../../../utils/markdown/useMarkdownCreationFilesInput';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import { splitMultilines } from '../../../../utils/String';
import { parse } from '../../../../utils/Time';
import ConfidenceField from '../../common/form/ConfidenceField';
import CreatedByField from '../../common/form/CreatedByField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import OpenVocabField from '../../common/form/OpenVocabField';
import StixCoreObjectsField from '../../common/form/StixCoreObjectsField';
import { ProcedureCreationMutation, ProcedureCreationMutation$variables } from './__generated__/ProcedureCreationMutation.graphql';

const procedureMutation = graphql`
  mutation ProcedureCreationMutation($input: ProcedureAddInput!) {
    procedureAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
      description
      entity_type
      parent_types
      ...ProceduresLine_node
    }
  }
`;

interface ProcedureAddInput {
  name: string;
  description: string;
  x_procedure_type: string | null;
  x_mitre_platforms: string[];
  killChainPhases: FieldOption[];
  techniques: FieldOption[];
  procedureObservables: FieldOption[];
  procedureCommand: FieldOption | null;
  procedureSources: FieldOption[];
  first_observed: Date | null;
  last_observed: Date | null;
  x_execution_start: Date | null;
  x_execution_end: Date | null;
  createdBy: FieldOption | null;
  objectMarking: FieldOption[];
  externalReferences: FieldOption[];
  confidence: number | null;
}

interface ProcedureFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  inputValue?: string;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

const PROCEDURE_TYPE = 'Procedure';

const formatDate = (date: Date | null) => (date ? parse(date).format() : null);

export const ProcedureCreationForm: FunctionComponent<ProcedureFormProps> = ({
  updater,
  onReset,
  inputValue,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  bulkModalOpen = false,
  onBulkModalClose,
}) => {
  const { t_i18n } = useFormatter();
  const [progressBarOpen, setProgressBarOpen] = useState(false);

  const { mandatoryAttributes } = useIsMandatoryAttribute(PROCEDURE_TYPE);
  const dateSchema = Yup.date()
    .nullable()
    .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'));
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    x_procedure_type: Yup.string().nullable(),
    x_mitre_platforms: Yup.array().nullable(),
    first_observed: dateSchema,
    last_observed: dateSchema,
    x_execution_start: dateSchema,
    x_execution_end: dateSchema,
  }, mandatoryAttributes);
  const procedureValidator = useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);

  const [commit] = useApiMutation<ProcedureCreationMutation>(
    procedureMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Procedure')} ${t_i18n('successfully created')}` },
  );
  const { buildCreationFilesInput, registerMarkdownImagesController } = useMarkdownCreationFilesInput();
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<ProcedureCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'procedureAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<ProcedureAddInput>['onSubmit'] = (
    values: ProcedureAddInput,
    { setSubmitting, setErrors, resetForm }: FormikHelpers<ProcedureAddInput>,
  ) => {
    const allNames = splitMultilines(values.name);
    const variables: ProcedureCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        ...getCustomFieldValues(values),
        ...buildCreationFilesInput([]),
        name,
        description: values.description,
        x_procedure_type: values.x_procedure_type,
        x_mitre_platforms: values.x_mitre_platforms,
        killChainPhases: values.killChainPhases.map((v) => v.value),
        techniques: values.techniques.map((v) => v.value),
        procedureObservables: values.procedureObservables.map((v) => v.value),
        procedureCommand: values.procedureCommand?.value,
        procedureSources: values.procedureSources.map((v) => v.value),
        first_observed: formatDate(values.first_observed),
        last_observed: formatDate(values.last_observed),
        x_execution_start: formatDate(values.x_execution_start),
        x_execution_end: formatDate(values.x_execution_end),
        createdBy: values.createdBy?.value,
        objectMarking: values.objectMarking.map((v) => v.value),
        externalReferences: values.externalReferences.map((v) => v.value),
        confidence: parseInt(String(values.confidence), 10),
      },
    }));

    bulkCommit({
      variables,
      onStepError: (error) => {
        handleErrorInForm(error, setErrors);
      },
      onCompleted: (total: number) => {
        setSubmitting(false);
        if (total < 2) {
          resetForm();
          onCompleted?.();
        }
      },
    });
  };

  const initialValues = useDefaultValues<ProcedureAddInput>(
    PROCEDURE_TYPE,
    {
      name: inputValue || '',
      description: '',
      x_procedure_type: null,
      x_mitre_platforms: [],
      killChainPhases: [],
      techniques: [],
      procedureObservables: [],
      procedureCommand: null,
      procedureSources: [],
      first_observed: null,
      last_observed: null,
      x_execution_start: null,
      x_execution_end: null,
      createdBy: defaultCreatedBy ?? null,
      objectMarking: defaultMarkingDefinitions ?? [],
      externalReferences: [],
      confidence: defaultConfidence ?? null,
    },
  );

  const dateField = (name: string, label: string) => (
    <Field
      component={DateTimePickerField}
      name={name}
      textFieldProps={{
        label,
        required: mandatoryAttributes.includes(name),
        variant: 'outlined',
        fullWidth: true,
        style: { ...fieldSpacingContainerStyle },
      }}
    />
  );

  return (
    <Formik<ProcedureAddInput>
      entityType={PROCEDURE_TYPE}
      initialValues={initialValues}
      validationSchema={procedureValidator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values, resetForm }) => (
        <>
          <BulkTextModal
            open={bulkModalOpen}
            onClose={onBulkModalClose}
            onValidate={async (val) => {
              await setFieldValue('name', val);
            }}
            formValue={values.name}
          />
          <ProgressBar
            open={progressBarOpen}
            value={(bulkCurrentCount / bulkCount) * 100}
            label={`${bulkCurrentCount}/${bulkCount}`}
            title={t_i18n('Create multiple entities')}
            onClose={() => {
              setProgressBarOpen(false);
              resetForm();
              resetBulk();
              onCompleted?.();
            }}
          >
            <BulkResult variablesToString={(v) => v.input.name} />
          </ProgressBar>
          <Form>
            <Field
              component={BulkTextField}
              name="name"
              label={t_i18n('Name')}
              required={mandatoryAttributes.includes('name')}
              fullWidth={true}
              detectDuplicate={[PROCEDURE_TYPE]}
            />
            <ConfidenceField
              entityType={PROCEDURE_TYPE}
              containerStyle={fieldSpacingContainerStyle}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              required={mandatoryAttributes.includes('description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={fieldSpacingContainerStyle}
              autoPersistOnBlur={false}
              registerMarkdownImagesController={registerMarkdownImagesController}
              uploadFileMarkings={values.objectMarking.map(({ value }) => value)}
            />
            <OpenVocabField
              label={t_i18n('Procedure type')}
              type="procedure_type_ov"
              name="x_procedure_type"
              required={mandatoryAttributes.includes('x_procedure_type')}
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              multiple={false}
            />
            <OpenVocabField
              label={t_i18n('Platforms')}
              type="platforms_ov"
              name="x_mitre_platforms"
              required={mandatoryAttributes.includes('x_mitre_platforms')}
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              multiple={true}
            />
            <KillChainPhasesField
              name="killChainPhases"
              required={mandatoryAttributes.includes('killChainPhases')}
              style={fieldSpacingContainerStyle}
            />
            <StixCoreObjectsField
              name="techniques"
              label={t_i18n('Techniques')}
              types={['Attack-Pattern']}
              style={fieldSpacingContainerStyle}
            />
            <StixCoreObjectsField
              name="procedureObservables"
              label={t_i18n('Observables')}
              types={['Stix-Cyber-Observable']}
              required={mandatoryAttributes.includes('procedureObservables')}
              style={fieldSpacingContainerStyle}
            />
            <StixCoreObjectsField
              name="procedureCommand"
              label={t_i18n('Command')}
              types={['Process']}
              multiple={false}
              required={mandatoryAttributes.includes('procedureCommand')}
              style={fieldSpacingContainerStyle}
            />
            <StixCoreObjectsField
              name="procedureSources"
              label={t_i18n('Sources')}
              types={['Identity']}
              required={mandatoryAttributes.includes('procedureSources')}
              style={fieldSpacingContainerStyle}
            />
            {dateField('first_observed', t_i18n('First observed'))}
            {dateField('last_observed', t_i18n('Last observed'))}
            {dateField('x_execution_start', t_i18n('Execution start'))}
            {dateField('x_execution_end', t_i18n('Execution end'))}
            <CreatedByField
              name="createdBy"
              style={fieldSpacingContainerStyle}
              required={mandatoryAttributes.includes('createdBy')}
              setFieldValue={setFieldValue}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={fieldSpacingContainerStyle}
              required={mandatoryAttributes.includes('objectMarking')}
              setFieldValue={setFieldValue}
            />
            <ExternalReferencesField
              name="externalReferences"
              style={fieldSpacingContainerStyle}
              required={mandatoryAttributes.includes('externalReferences')}
              setFieldValue={setFieldValue}
              values={values.externalReferences}
            />
            <CustomFieldValuesCreation />
            <FormButtonContainer>
              <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button onClick={submitForm} disabled={isSubmitting}>
                {t_i18n('Create')}
              </Button>
            </FormButtonContainer>
          </Form>
        </>
      )}
    </Formik>
  );
};

const ProcedureCreation: FunctionComponent<{
  contextual?: boolean;
  display?: boolean;
  inputValue?: string;
  paginationOptions: ProceduresLinesPaginationQuery$variables;
}> = ({
  contextual,
  display,
  inputValue,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_procedures',
    paginationOptions,
    'procedureAdd',
  );
  const CreateProcedureControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType={PROCEDURE_TYPE} {...props} />
  );
  const CreateProcedureControlledDialContextual = CreateProcedureControlledDial({
    onOpen: handleOpen,
    onClose: () => {},
  });
  const renderClassic = () => (
    <Drawer
      title={t_i18n('Create a procedure')}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={CreateProcedureControlledDial}
    >
      {({ onClose }) => (
        <ProcedureCreationForm
          inputValue={inputValue}
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
        />
      )}
    </Drawer>
  );
  const renderContextual = () => (
    <div style={{ display: display ? 'block' : 'none' }}>
      {CreateProcedureControlledDialContextual}
      <Dialog
        open={open}
        onClose={handleClose}
        title={(
          <Stack direction="row" sx={{ justifyContent: 'space-between', alignContent: 'center' }}>
            {t_i18n('Create a procedure')}
            <BulkTextModalButton onClick={() => setBulkOpen(true)} />
          </Stack>
        )}
      >
        <ProcedureCreationForm
          inputValue={inputValue}
          updater={updater}
          onCompleted={handleClose}
          onReset={handleClose}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
        />
      </Dialog>
    </div>
  );

  if (contextual) {
    return renderContextual();
  }
  return renderClassic();
};

export default ProcedureCreation;
