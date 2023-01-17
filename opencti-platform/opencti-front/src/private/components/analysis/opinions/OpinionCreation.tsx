import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import { handleErrorInForm } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import MarkDownField from '../../../../components/MarkDownField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { insertNode } from '../../../../utils/store';
import { Option } from '../../common/form/ReferenceField';
import { OpinionsLinesPaginationQuery$variables } from './__generated__/OpinionsLinesPaginationQuery.graphql';
import { Theme } from '../../../../components/Theme';

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
    right: 30,
  },
  createButtonContextual: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
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

export const opinionCreationMutation = graphql`
  mutation OpinionCreationMutation($input: OpinionAddInput!) {
    opinionAdd(input: $input) {
      ...OpinionLine_node
    }
  }
`;

const opinionValidation = (t: (message: string) => string) => Yup.object().shape({
  opinion: Yup.string().required(t('This field is required')),
  explanation: Yup.string().required(t('This field is required')),
  confidence: Yup.number(),
});

interface OpinionAddInput {
  opinion: string
  explanation: string
  createdBy: Option | undefined
  objectMarking: Option[]
  objectLabel: Option[]
  confidence: number
}

interface OpinionCreationProps {
  contextual?: boolean
  display?: boolean
  inputValue?: string
  paginationOptions: OpinionsLinesPaginationQuery$variables
}

const OpinionCreation: FunctionComponent<OpinionCreationProps> = ({
  contextual,
  display,
  inputValue,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const onReset = () => handleClose();

  const initialValues: OpinionAddInput = {
    opinion: inputValue || '',
    explanation: '',
    createdBy: '' as unknown as Option,
    objectMarking: [],
    objectLabel: [],
    confidence: 75,
  };

  const [commit] = useMutation(opinionCreationMutation);

  const onSubmit: FormikConfig<OpinionAddInput>['onSubmit'] = (
    values: OpinionAddInput,
    {
      setSubmitting,
      setErrors,
      resetForm,
    }: FormikHelpers<OpinionAddInput>,
  ) => {
    const finalValues = {
      opinion: values.opinion,
      explanation: values.explanation,
      confidence: parseInt(String(values.confidence), 10),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
    };
    commit({
      variables: {
        input: finalValues,
      },
      updater: (store) => insertNode(
        store,
        'Pagination_opinions',
        paginationOptions,
        'opinionAdd',
      ),
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };

  const fields = (
    setFieldValue: (
      field: string,
      value: unknown,
      shouldValidate?: boolean | undefined
    ) => void,
    values: OpinionAddInput,
  ) => (
    <>
      <OpenVocabField
        label={t('Opinion')}
        type="opinion_ov"
        name="opinion"
        onChange={(name, value) => setFieldValue(name, value)}
        containerStyle={fieldSpacingContainerStyle}
        multiple={false}
      />
      <Field
        component={MarkDownField}
        name="explanation"
        label={t('Explanation')}
        fullWidth={true}
        multiline={true}
        rows="4"
        style={{ marginTop: 20 }}
      />
      <CreatedByField
        name="createdBy"
        style={fieldSpacingContainerStyle}
        setFieldValue={setFieldValue}
      />
      <ConfidenceField
        name="confidence"
        label={t('Confidence')}
        fullWidth={true}
        containerStyle={fieldSpacingContainerStyle}
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
    </>
  );

  const renderClassic = () => {
    return (
      <div>
        <Fab
          onClick={handleOpen}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={open}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleClose}
        >
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
            <Typography variant="h6">{t('Create a opinions')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik<OpinionAddInput>
              initialValues={initialValues}
              validationSchema={opinionValidation(t)}
              onSubmit={onSubmit}
              onReset={onReset}
            >
              {({
                submitForm,
                handleReset,
                isSubmitting,
                setFieldValue,
                values,
              }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  {fields(setFieldValue, values)}
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
  const renderContextual = () => {
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        <Fab
          onClick={handleOpen}
          color="secondary"
          aria-label="Add"
          className={classes.createButtonContextual}
        >
          <Add />
        </Fab>
        <Dialog
          open={open}
          onClose={handleClose}
          PaperProps={{ elevation: 1 }}
        >
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={opinionValidation(t)}
            onSubmit={onSubmit}
            onReset={onReset}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form>
                <DialogTitle>{t('Create an opinion')}</DialogTitle>
                <DialogContent>
                  {fields(setFieldValue, values)}
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
      </div>
    );
  };

  if (contextual) {
    return renderContextual();
  }
  return renderClassic();
};

export default OpinionCreation;
