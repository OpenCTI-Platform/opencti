import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import { SimpleFileUpload } from 'formik-mui';
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
import MarkDownField from '../../../../components/MarkDownField';
import { Theme } from '../../../../components/Theme';
import { FeedbackCreationMutation$variables } from './__generated__/FeedbackCreationMutation.graphql';
import { MESSAGING$ } from '../../../../relay/environment';
import StixCoreObjectsField from '../../common/form/StixCoreObjectsField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import RatingField from '../../../../components/RatingField';
import useAuth from '../../../../utils/hooks/useAuth';
import ConfidenceField from '../../common/form/ConfidenceField';
import { Option } from '../../common/form/ReferenceField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

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
  mutation FeedbackCreationMutation($input: CaseAddInput!) {
    caseAdd(input: $input) {
      ...FeedbackLine_node
    }
  }
`;

const caseValidation = () => Yup.object().shape({
  description: Yup.string().nullable(),
  confidence: Yup.number(),
  rating: Yup.number(),
});

interface FormikCaseAddInput {
  description: string
  confidence: number
  rating: number
  objects: { value: string }[]
  file: File | undefined
  objectLabel: Option[]
}

const FeedbackCreation: FunctionComponent<{
  openDrawer: boolean;
  handleCloseDrawer: () => void;
}> = ({ openDrawer, handleCloseDrawer }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { me } = useAuth();
  const [commit] = useMutation(feedbackMutation);
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const onSubmit: FormikConfig<FormikCaseAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const finalValues: FeedbackCreationMutation$variables['input'] = {
      name: `Feedback from ${me.user_email}`,
      case_type: 'feedback',
      description: values.description,
      confidence: parseInt(String(values.confidence), 10),
      rating: parseInt(String(values.rating), 6),
      objects: values.objects.map((o) => o.value),
      objectLabel: values.objectLabel.map((v) => v.value),
    };
    if (values.file) {
      finalValues.file = values.file;
    }
    commit({
      variables: {
        input: finalValues,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseDrawer();
        MESSAGING$.notifySuccess('Thank you for your feedback!');
      },
    });
  };
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
          <Formik<FormikCaseAddInput>
            initialValues={{
              rating: 5,
              description: '',
              confidence: 75,
              objects: [],
              file: undefined,
              objectLabel: [],
            }}
            validationSchema={caseValidation()}
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
                  component={MarkDownField}
                  name="description"
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                />
                <ConfidenceField
                  name="confidence"
                  label={t('Confidence')}
                  fullWidth={true}
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
                <Field
                  component={SimpleFileUpload}
                  name="file"
                  label={t('Associated file')}
                  FormControlProps={{ style: { marginTop: 20, width: '100%' } }}
                  InputLabelProps={{ fullWidth: true, variant: 'standard' }}
                  InputProps={{ fullWidth: true, variant: 'standard' }}
                  fullWidth={true}
                />
                <ObjectLabelField
                  name="objectLabel"
                  style={{ marginTop: userIsKnowledgeEditor ? 20 : 10 }}
                  setFieldValue={setFieldValue}
                  values={values.objectLabel}
                />
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
        </div>
      </Drawer>
    </div>
  );
};

export default FeedbackCreation;
