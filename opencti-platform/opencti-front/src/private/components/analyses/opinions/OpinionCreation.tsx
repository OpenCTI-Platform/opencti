import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import Button from '@common/button/Button';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { handleErrorInForm } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import type { Theme } from '../../../../components/Theme';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { OpinionCreationMutation$variables } from './__generated__/OpinionCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { yupShapeConditionalRequired, useDynamicSchemaCreationValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';

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

export const opinionCreationUserMutation = graphql`
  mutation OpinionCreationUserMutation($input: OpinionUserAddInput!) {
    userOpinionAdd(input: $input) {
      id
      representative {
        main
      }
      standard_id
      entity_type
      parent_types
      opinion
      explanation
      ...OpinionLine_node
    }
  }
`;

export const opinionCreationMutation = graphql`
  mutation OpinionCreationMutation($input: OpinionAddInput!) {
    opinionAdd(input: $input) {
      id
      representative {
        main
      }
      standard_id
      entity_type
      parent_types
      opinion
      explanation
      ...OpinionLine_node
    }
  }
`;

interface OpinionAddInput {
  opinion: string;
  explanation: string;
  confidence: number | undefined;
  createdBy?: FieldOption;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  file: File | undefined;
}

interface OpinionFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: FieldOption;
  defaultMarkingDefinitions?: FieldOption[];
  defaultConfidence?: number;
  inputValue?: string;
}

const OPINION_TYPE = 'Opinion';

export const OpinionCreationFormKnowledgeEditor: FunctionComponent<OpinionFormProps> = ({
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
  const { mandatoryAttributes } = useIsMandatoryAttribute(OPINION_TYPE);
  const basicShape = yupShapeConditionalRequired({
    opinion: Yup.string(),
    explanation: Yup.string().nullable(),
    confidence: Yup.number(),
  }, mandatoryAttributes);
  const opinionValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
    ['createdBy'],
  );

  const [commit] = useApiMutation(opinionCreationMutation);
  const onSubmit: FormikConfig<OpinionAddInput>['onSubmit'] = (
    values: OpinionAddInput,
    { setSubmitting, setErrors, resetForm }: FormikHelpers<OpinionAddInput>,
  ) => {
    const input: OpinionCreationMutation$variables['input'] = {
      opinion: values.opinion,
      explanation: values.explanation,
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
      updater: (store) => {
        if (updater) {
          updater(store, 'opinionAdd');
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

  const initialValues = useDefaultValues<OpinionAddInput>(
    OPINION_TYPE,
    {
      opinion: inputValue ?? '',
      explanation: '',
      confidence: defaultConfidence,
      createdBy: defaultCreatedBy,
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
      externalReferences: [],
      file: undefined,
    },
  );

  return (
    <Formik<OpinionAddInput>
      initialValues={initialValues}
      validationSchema={opinionValidator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form>
          <OpenVocabField
            label={t_i18n('Opinion')}
            type="opinion_ov"
            name="opinion"
            required={(mandatoryAttributes.includes('opinion'))}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
          />
          <Field
            component={MarkdownField}
            name="explanation"
            label={t_i18n('Explanation')}
            required={(mandatoryAttributes.includes('explanation'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
          />
          <ConfidenceField
            entityType="Opinion"
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

export const OpinionCreationFormKnowledgeParticipant: FunctionComponent<OpinionFormProps> = ({
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
  const { mandatoryAttributes } = useIsMandatoryAttribute(OPINION_TYPE);
  const basicShape = yupShapeConditionalRequired({
    opinion: Yup.string(),
    explanation: Yup.string().nullable(),
    confidence: Yup.number(),
  }, mandatoryAttributes);
  const opinionValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
    ['createdBy'],
  );

  const [commit] = useApiMutation(opinionCreationUserMutation);
  const onSubmit: FormikConfig<OpinionAddInput>['onSubmit'] = (
    values: OpinionAddInput,
    { setSubmitting, setErrors, resetForm }: FormikHelpers<OpinionAddInput>,
  ) => {
    const finalValues: OpinionCreationMutation$variables['input'] = {
      opinion: values.opinion,
      explanation: values.explanation,
      confidence: parseInt(String(values.confidence), 10),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      externalReferences: values.externalReferences.map(({ value }) => value),
    };
    if (values.file) {
      finalValues.file = values.file;
    }
    commit({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'userOpinionAdd');
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

  const initialValues = useDefaultValues<OpinionAddInput>(
    OPINION_TYPE,
    {
      opinion: inputValue ?? '',
      explanation: '',
      confidence: defaultConfidence,
      createdBy: defaultCreatedBy,
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
      externalReferences: [],
      file: undefined,
    },
  );

  return (
    <Formik<OpinionAddInput>
      initialValues={initialValues}
      validationSchema={opinionValidator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form>
          <OpenVocabField
            label={t_i18n('Opinion')}
            type="opinion_ov"
            name="opinion"
            required={(mandatoryAttributes.includes('opinion'))}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
          />
          <Field
            component={MarkdownField}
            name="explanation"
            label={t_i18n('Explanation')}
            required={(mandatoryAttributes.includes('explanation'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
          />
          <ConfidenceField
            entityType="Opinion"
            containerStyle={fieldSpacingContainerStyle}
          />
          <ObjectLabelField
            name="objectLabel"
            required={(mandatoryAttributes.includes('objectLabel'))}
            style={{ marginTop: 10 }}
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
