import Button from '@common/button/Button';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { ObservedDatasLinesPaginationQuery$variables } from '@components/events/__generated__/ObservedDatasLinesPaginationQuery.graphql';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { handleErrorInForm } from '../../../../relay/environment';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import { parse } from '../../../../utils/Time';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import ConfidenceField from '../../common/form/ConfidenceField';
import CreatedByField from '../../common/form/CreatedByField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import StixCoreObjectsField from '../../common/form/StixCoreObjectsField';
import { ObservedDataCreationMutation, ObservedDataCreationMutation$variables } from './__generated__/ObservedDataCreationMutation.graphql';

const observedDataCreationMutation = graphql`
  mutation ObservedDataCreationMutation($input: ObservedDataAddInput!) {
    observedDataAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
      entity_type
      parent_types
      ...ObservedDatasLine_node
    }
  }
`;

const OBSERVED_DATA_TYPE = 'Observed-Data';

interface ObservedDataAddInput {
  objects: { value: string }[];
  first_observed: Date | null;
  last_observed: Date | null;
  number_observed: number;
  confidence: number | undefined;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  file: File | undefined;
}

interface ObservedDataFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
    response: { id: string; name: string } | null,
  ) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
}

export const ObservedDataCreationForm: FunctionComponent<
  ObservedDataFormProps
> = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(OBSERVED_DATA_TYPE);
  const basicShape = yupShapeConditionalRequired({
    objects: Yup.array(),
    first_observed: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_observed: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    number_observed: Yup.number(),
    confidence: Yup.number().nullable(),
  }, mandatoryAttributes);
  const observedDataValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
  );
  const [commit] = useApiMutation<ObservedDataCreationMutation>(
    observedDataCreationMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Observed-Data')} ${t_i18n('successfully created')}` },
  );
  const onSubmit: FormikConfig<ObservedDataAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: ObservedDataCreationMutation$variables['input'] = {
      objects: values.objects.map((v) => v.value),
      first_observed: parse(values.first_observed).format(),
      last_observed: parse(values.last_observed).format(),
      number_observed: parseInt(String(values.number_observed), 10),
      confidence: parseInt(String(values.confidence), 10),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store, response) => {
        if (updater && response) {
          updater(store, 'observedDataAdd', response.observedDataAdd ?? null);
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
  const initialValues = useDefaultValues(OBSERVED_DATA_TYPE, {
    objects: [],
    first_observed: null,
    last_observed: null,
    number_observed: 1,
    confidence: defaultConfidence,
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
  });
  return (
    <Formik<ObservedDataAddInput>
      initialValues={initialValues}
      validationSchema={observedDataValidator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form>
          <StixCoreObjectsField
            name="objects"
            style={fieldSpacingContainerStyle}
            required={(mandatoryAttributes.includes('objects'))}
          />
          <Field
            component={DateTimePickerField}
            name="first_observed"
            textFieldProps={{
              label: t_i18n('First observed'),
              required: (mandatoryAttributes.includes('first_observed')),
              variant: 'standard',
              fullWidth: true,
              style: { ...fieldSpacingContainerStyle },
            }}
          />
          <Field
            component={DateTimePickerField}
            name="last_observed"
            textFieldProps={{
              label: t_i18n('Last observed'),
              required: (mandatoryAttributes.includes('last_observed')),
              variant: 'standard',
              fullWidth: true,
              style: { ...fieldSpacingContainerStyle },
            }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="number_observed"
            type="number"
            label={t_i18n('Number observed')}
            required={(mandatoryAttributes.includes('number_observed'))}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
          />
          <ConfidenceField
            entityType="Observed-Data"
            containerStyle={fieldSpacingContainerStyle}
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
          <FormButtonContainer>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
            >
              {t_i18n('Create')}
            </Button>
          </FormButtonContainer>
        </Form>
      )}
    </Formik>
  );
};

const ObservedDataCreation = ({
  paginationOptions,
}: {
  paginationOptions: ObservedDatasLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_observedDatas',
    paginationOptions,
    'observedDataAdd',
  );
  const CreateObservedDataControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Observed-Data" {...props} />
  );
  return (
    <Drawer
      title={t_i18n('Create an observed data')}
      controlledDial={CreateObservedDataControlledDial}
    >
      {({ onClose }) => (
        <ObservedDataCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default ObservedDataCreation;
