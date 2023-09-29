import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { handleErrorInForm } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import MarkdownField from '../../../../components/MarkdownField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { insertNode } from '../../../../utils/store';
import { Option } from '../../common/form/ReferenceField';
import { OpinionsLinesPaginationQuery$variables } from './__generated__/OpinionsLinesPaginationQuery.graphql';
import { Theme } from '../../../../components/Theme';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { OpinionCreationMutation$variables } from './__generated__/OpinionCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';

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
  opinion: string
  explanation: string
  confidence: number | undefined
  createdBy?: Option
  objectMarking: Option[]
  objectLabel: Option[]
  externalReferences: { value: string }[]
  file: File | undefined
}

interface OpinionCreationProps {
  paginationOptions: OpinionsLinesPaginationQuery$variables;
}

interface OpinionFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: Option;
  defaultMarkingDefinitions?: Option[];
  defaultConfidence?: number;
}

const OPINION_TYPE = 'Opinion';

export const OpinionCreationFormKnowledgeEditor: FunctionComponent<OpinionFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    opinion: Yup.string().required(t('This field is required')),
    explanation: Yup.string().nullable(),
    confidence: Yup.number(),
  };
  const opinionValidator = useSchemaCreationValidation(
    OPINION_TYPE,
    basicShape,
    ['createdBy'],
  );

  const [commit] = useMutation(opinionCreationMutation);
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
      opinion: '',
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
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <OpenVocabField
            label={t('Opinion')}
            type="opinion_ov"
            name="opinion"
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
          />
          <Field
            component={MarkdownField}
            name="explanation"
            label={t('Explanation')}
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
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
          />
          <ExternalReferencesField
            name="externalReferences"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <CustomFileUploader setFieldValue={setFieldValue} />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Create')}
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
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    opinion: Yup.string().required(t('This field is required')),
    explanation: Yup.string().nullable(),
    confidence: Yup.number(),
  };
  const opinionValidator = useSchemaCreationValidation(
    OPINION_TYPE,
    basicShape,
    ['createdBy'],
  );

  const [commit] = useMutation(opinionCreationUserMutation);
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
      opinion: '',
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
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <OpenVocabField
            label={t('Opinion')}
            type="opinion_ov"
            name="opinion"
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
          />
          <Field
            component={MarkdownField}
            name="explanation"
            label={t('Explanation')}
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
            style={{ marginTop: 10 }}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
          />
          <ExternalReferencesField
            name="externalReferences"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <CustomFileUploader setFieldValue={setFieldValue} />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

const OpinionCreation: FunctionComponent<OpinionCreationProps> = ({
  paginationOptions,
}) => {
  const { t } = useFormatter();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const updater = (store: RecordSourceSelectorProxy, key: string) => insertNode(store, 'Pagination_opinions', paginationOptions, key);

  return (
    <Drawer
      title={t('Create a opinions')}
      variant={DrawerVariant.create}
    >
      {({ onClose }) => (
        <>
          {userIsKnowledgeEditor
            ? <OpinionCreationFormKnowledgeEditor
              updater={updater}
              onCompleted={onClose}
              onReset={onClose}
            />
            : <OpinionCreationFormKnowledgeParticipant
              updater={updater}
              onCompleted={onClose}
              onReset={onClose}
            />
          }
        </>
      )}
    </Drawer>
  );
};

export default OpinionCreation;
