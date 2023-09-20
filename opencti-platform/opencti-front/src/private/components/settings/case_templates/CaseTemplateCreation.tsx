import { Add, Close } from '@mui/icons-material';
import Button from '@mui/material/Button';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import TextField from '../../../../components/TextField';
import { Theme } from '../../../../components/Theme';
import { insertNode } from '../../../../utils/store';
import CaseTemplateTasks from '../../common/form/CaseTemplateTasks';
import { CaseTemplateAddInput } from './__generated__/CaseTemplateCreationMutation.graphql';
import { CaseTemplateLinesPaginationQuery$variables } from './__generated__/CaseTemplateLinesPaginationQuery.graphql';

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
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

const caseTemplateMutation = graphql`
  mutation CaseTemplateCreationMutation($input: CaseTemplateAddInput!) {
    caseTemplateAdd(input: $input) {
      ...CaseTemplateLine_node
    }
  }
`;

const caseTemplateValidation = (t: (name: string | object) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  tasks: Yup.array(),
});

interface CaseTemplateCreationProps {
  paginationOptions?: CaseTemplateLinesPaginationQuery$variables;
}

const CaseTemplateCreation: FunctionComponent<CaseTemplateCreationProps> = ({
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [open, setOpen] = useState(false);

  const handleOpen = () => setOpen(true);

  const handleClose = () => setOpen(false);

  const [commitMutation] = useMutation(caseTemplateMutation);

  const onSubmit: FormikConfig<CaseTemplateAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const input = { ...values, tasks: values.tasks.map(({ value }) => value) };
    setSubmitting(true);
    commitMutation({
      variables: { input },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_caseTemplates',
          paginationOptions,
          'caseTemplateAdd',
        );
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };

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
        sx={{ zIndex: 1202 }}
        elevation={1}
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
          <Typography variant="h6">{t('Create a case template')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik
            initialValues={{
              name: '',
              description: '',
              tasks: [],
            }}
            validationSchema={caseTemplateValidation(t)}
            onSubmit={onSubmit}
            onReset={handleClose}
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
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t('Name')}
                  fullWidth={true}
                />
                <Field
                  component={MarkdownField}
                  name="description"
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 20 }}
                />
                <CaseTemplateTasks
                  onChange={setFieldValue}
                  values={values.tasks}
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

export default CaseTemplateCreation;
