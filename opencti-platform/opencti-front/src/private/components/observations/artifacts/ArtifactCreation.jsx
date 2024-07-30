import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useHelper from '../../../../utils/hooks/useHelper';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
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
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
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

const artifactMutation = graphql`
  mutation ArtifactCreationMutation(
    $file: Upload!
    $x_opencti_description: String
    $createdBy: String
    $objectMarking: [String]
    $objectLabel: [String]
  ) {
    artifactImport(
      file: $file
      x_opencti_description: $x_opencti_description
      createdBy: $createdBy
      objectMarking: $objectMarking
      objectLabel: $objectLabel
    ) {
      ...ArtifactsLine_node
    }
  }
`;

const artifactValidation = (t) => Yup.object().shape({
  file: Yup.mixed().required(t('This field is required')),
  x_opencti_description: Yup.string().nullable(),
});

const ArtifactCreation = ({
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const [open, setOpen] = useState(false);
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const [commit] = useApiMutation(
    artifactMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Artifact')} ${t_i18n('successfully created')}` },
  );

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  const onSubmit = (values, { setSubmitting, setErrors, resetForm }) => {
    const adaptedValues = R.evolve(
      {
        createdBy: R.path(['value']),
        objectMarking: R.pluck('value'),
        objectLabel: R.pluck('value'),
      },
      values,
    );
    commit({
      variables: {
        file: values.file,
        ...adaptedValues,
      },
      updater: (store) => insertNode(
        store,
        'Pagination_stixCyberObservables',
        paginationOptions,
        'artifactImport',
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

  const onReset = () => {
    handleClose();
  };

  return (
    <>
      {isFABReplaced
        ? <CreateEntityControlledDial
            entityType='Artifact'
            onOpen={handleOpen}
          />
        : <Fab
            onClick={handleOpen}
            color="primary"
            aria-label="Add"
            className={classes.createButton}
          >
          <Add />
        </Fab>}
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
          <Typography variant="h6">{t_i18n('Create an artifact')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik
            initialValues={{
              x_opencti_description: '',
              file: '',
              createdBy: '',
              objectMarking: [],
              objectLabel: [],
            }}
            validationSchema={artifactValidation(t_i18n)}
            onSubmit={onSubmit}
            onReset={onReset}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
              errors,
            }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <CustomFileUploader setFieldValue={setFieldValue} formikErrors={errors}/>
                <Field
                  component={MarkdownField}
                  name="x_opencti_description"
                  label={t_i18n('Description')}
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
                <div className={classes.buttons}>
                  <Button
                    variant="contained"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
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
        </div>
      </Drawer>
    </>
  );
};

export default ArtifactCreation;
