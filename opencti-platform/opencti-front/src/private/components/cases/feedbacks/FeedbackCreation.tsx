import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import { Theme } from '../../../../components/Theme';
import { MESSAGING$ } from '../../../../relay/environment';
import StixCoreObjectsField from '../../common/form/StixCoreObjectsField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import RatingField from '../../../../components/RatingField';
import useAuth from '../../../../utils/hooks/useAuth';
import ConfidenceField from '../../common/form/ConfidenceField';
import { Option } from '../../common/form/ReferenceField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { FeedbackCreationMutation$variables } from './__generated__/FeedbackCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
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
}));

const feedbackMutation = graphql`
  mutation FeedbackCreationMutation($input: FeedbackAddInput!) {
    feedbackAdd(input: $input) {
      ...FeedbackLine_node
    }
  }
`;

interface FormikFeedbackAddInput {
  name: string
  description: string
  confidence: number | undefined
  rating: number | null
  objects: { value: string }[]
  file: File | undefined
  objectLabel: Option[]
}

const FEEDBACK_TYPE = 'Feedback';

const FeedbackCreation: FunctionComponent<{
  openDrawer: boolean;
  handleCloseDrawer: () => void;
}> = ({ openDrawer, handleCloseDrawer }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { me } = useAuth();
  const [commit] = useMutation(feedbackMutation);
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);

  const basicShape = {
    description: Yup.string().nullable(),
    confidence: Yup.number(),
    rating: Yup.number(),
  };
  const feedbackValidator = useSchemaCreationValidation(FEEDBACK_TYPE, basicShape);

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
        MESSAGING$.notifySuccess('Thank you for your feedback!');
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
    },
    { rating: 5 },
  );

  return (
    <div>
      <Drawer
        open={openDrawer}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleCloseDrawer}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleCloseDrawer}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Submit a feedback')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik<FormikFeedbackAddInput>
            initialValues={initialValues}
            validationSchema={feedbackValidator}
            onSubmit={onSubmit}
            onReset={handleCloseDrawer}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={MarkdownField}
                  name="description"
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                />
                <ConfidenceField
                  entityType="Feedback"
                  containerStyle={fieldSpacingContainerStyle}
                />
                <RatingField
                  label={t('Rating')}
                  rating={values.rating}
                  size="small"
                  handleOnChange={(newValue) => {
                    setFieldValue('rating', newValue);
                  }}
                  style={fieldSpacingContainerStyle}
                />
                <StixCoreObjectsField
                  name="objects"
                  style={fieldSpacingContainerStyle}
                  setFieldValue={setFieldValue}
                  values={values.objects}
                />
                <CustomFileUploader setFieldValue={setFieldValue} />
                <ObjectLabelField
                  name="objectLabel"
                  style={{ marginTop: userIsKnowledgeEditor ? 20 : 10 }}
                  setFieldValue={setFieldValue}
                  values={values.objectLabel}
                />
                <div className={classes.buttons}>
                  <Button
                    onClick={handleReset}
                    disabled={isSubmitting}
                    variant="contained"
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
        </div>
      </Drawer>
    </div>
  );
};

export default FeedbackCreation;
