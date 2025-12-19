import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import StixCoreObjectsField from '../../common/form/StixCoreObjectsField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import RatingField from '../../../../components/fields/RatingField';
import useAuth from '../../../../utils/hooks/useAuth';
import ConfidenceField from '../../common/form/ConfidenceField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { FeedbackCreationMutation$variables } from './__generated__/FeedbackCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import SimpleMarkdownField from '../../../../components/SimpleMarkdownField';
import Drawer from '../../common/drawer/Drawer';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

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

const feedbackMutation = graphql`
  mutation FeedbackCreationMutation($input: FeedbackAddInput!) {
    feedbackAdd(input: $input) {
      ...FeedbacksLine_node
    }
  }
`;

interface FormikFeedbackAddInput {
  name: string;
  description: string;
  confidence: number | undefined;
  rating: number | null;
  objects: { value: string }[];
  file: File | undefined;
  objectLabel: FieldOption[];
}

const FEEDBACK_TYPE = 'Feedback';

const FeedbackCreation: FunctionComponent<{
  openDrawer: boolean;
  handleCloseDrawer: () => void;
  initialValue?: Partial<FormikFeedbackAddInput>;
}> = ({ openDrawer, handleCloseDrawer, initialValue }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const [commit] = useApiMutation(
    feedbackMutation,
    undefined,
    { successMessage: 'Thank you for your feedback!' },
  );
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);

  const { mandatoryAttributes } = useIsMandatoryAttribute(
    FEEDBACK_TYPE,
  );
  const basicShape = yupShapeConditionalRequired({
    description: Yup.string().nullable(),
    confidence: Yup.number(),
    rating: Yup.number().min(1).max(5),
  }, mandatoryAttributes);
  const validator = useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);

  const onSubmit: FormikConfig<FormikFeedbackAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const input: FeedbackCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      confidence: parseInt(String(values.confidence), 10),
      rating: parseInt(String(values.rating), 6),
      objects: values.objects.map((o) => o.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseDrawer();
      },
    });
  };

  const initialValues = useDefaultValues<FormikFeedbackAddInput>(
    FEEDBACK_TYPE,
    {
      name: `Feedback from ${me.user_email}`,
      rating: null,
      description: '',
      confidence: undefined,
      objects: [],
      file: undefined,
      objectLabel: [],
      ...initialValue,
    },
    { rating: 5 },
  );

  return (
    <Drawer
      title={t_i18n('Submit a feedback')}
      open={openDrawer}
      onClose={handleCloseDrawer}
    >
      <Formik<FormikFeedbackAddInput>
        initialValues={initialValues}
        validationSchema={validator}
        onSubmit={onSubmit}
        validateOnChange={true}
        validateOnBlur={true}
        onReset={handleCloseDrawer}
      >
        {({
          submitForm,
          handleReset,
          isSubmitting,
          setFieldValue,
          values,
        }) => (
          <Form>
            <Field
              component={SimpleMarkdownField}
              askAI={false}
              name="description"
              label={t_i18n('Description')}
              required={(mandatoryAttributes.includes('description'))}
              fullWidth={true}
              multiline={true}
              rows="4"
            />
            <ConfidenceField
              entityType="Feedback"
              containerStyle={fieldSpacingContainerStyle}
            />
            <RatingField
              label={t_i18n('Rating')}
              readOnly={false}
              required={(mandatoryAttributes.includes('rating'))}
              rating={values.rating}
              size="small"
              handleOnChange={(newValue) => {
                // Cannot remove the rating, always required and not customizable, and can only be 1-5 in value
                if (newValue != null && newValue >= 1 && newValue <= 5) {
                  setFieldValue('rating', newValue);
                }
              }}
              style={fieldSpacingContainerStyle}
            />
            <StixCoreObjectsField
              name="objects"
              required={(mandatoryAttributes.includes('objects'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              values={values.objects}
            />
            <CustomFileUploader setFieldValue={setFieldValue} />
            <ObjectLabelField
              name="objectLabel"
              required={(mandatoryAttributes.includes('objectLabel'))}
              style={{ marginTop: userIsKnowledgeEditor ? 20 : 10 }}
              setFieldValue={setFieldValue}
              values={values.objectLabel}
            />
            <div className={classes.buttons}>
              <Button
                onClick={handleReset}
                disabled={isSubmitting}
                variant="secondary"
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
    </Drawer>
  );
};

export default FeedbackCreation;
