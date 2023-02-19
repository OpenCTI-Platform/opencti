import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Button from '@mui/material/Button';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import Drawer from '@mui/material/Drawer';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { handleErrorInForm } from '../../../../relay/environment';
import { insertNode } from '../../../../utils/store';
import { Option } from '../../common/form/ReferenceField';
import { DataSourcesLinesPaginationQuery$variables } from './__generated__/DataSourcesLinesPaginationQuery.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';

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
  dialogActions: {
    padding: '0 17px 20px 0',
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

const dataSourceMutation = graphql`
  mutation DataSourceCreationMutation($input: DataSourceAddInput!) {
    dataSourceAdd(input: $input) {
      id
      name
      description
      entity_type
      ...DataSourceLine_node
    }
  }
`;

interface DataSourceAddInput {
  name: string;
  description: string;
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: Option[];
  confidence: number;
  x_mitre_platforms: string[];
  collection_layers: string[];
}

interface DataSourceCreationProps {
  contextual?: boolean;
  display?: boolean;
  inputValue?: string;
  paginationOptions: DataSourcesLinesPaginationQuery$variables;
}

interface DataSourceFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void
  onReset?: () => void
  onCompleted?: () => void
  inputValue?: string
  defaultCreatedBy?: Option
  defaultMarkingDefinitions?: Option[]
  defaultConfidence?: number
}

export const DataSourceCreationForm: FunctionComponent<DataSourceFormProps> = ({ updater, onReset, inputValue, onCompleted,
  defaultConfidence, defaultCreatedBy, defaultMarkingDefinitions }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
  };
  const dataSourceValidator = useSchemaCreationValidation('Data-Source', basicShape);
  const initialValues: DataSourceAddInput = {
    name: inputValue || '',
    description: '',
    createdBy: defaultCreatedBy ?? '' as unknown as Option,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    confidence: defaultConfidence ?? 75,
    x_mitre_platforms: [],
    collection_layers: [],
  };
  const [commit] = useMutation(dataSourceMutation);
  const onSubmit: FormikConfig<DataSourceAddInput>['onSubmit'] = (
    values: DataSourceAddInput,
    { setSubmitting, setErrors, resetForm }: FormikHelpers<DataSourceAddInput>,
  ) => {
    const finalValues = {
      name: values.name,
      description: values.description,
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      externalReferences: values.externalReferences.map((v) => v.value),
      confidence: parseInt(String(values.confidence), 10),
      x_mitre_platforms: values.x_mitre_platforms,
      collection_layers: values.collection_layers,
    };
    commit({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'dataSourceAdd');
        }
      },
      onError: (error: Error) => {
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

  return <Formik<DataSourceAddInput>
      initialValues={initialValues}
      validationSchema={dataSourceValidator}
      onSubmit={onSubmit}
      onReset={onReset}>
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
              detectDuplicate={['Data-Source']}
          />
          <ConfidenceField
              name="confidence"
              label={t('Confidence')}
              fullWidth={true}
              containerStyle={fieldSpacingContainerStyle}
          />
          <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
          />
          <CreatedByField
              name="createdBy"
              style={{
                marginTop: 20,
                width: '100%',
              }}
              setFieldValue={setFieldValue}
          />
          <ObjectLabelField
              name="objectLabel"
              style={{
                marginTop: 20,
                width: '100%',
              }}
              setFieldValue={setFieldValue}
              values={values.objectLabel}
          />
          <ObjectMarkingField
              name="objectMarking"
              style={{
                marginTop: 20,
                width: '100%',
              }}
          />
          <ExternalReferencesField
              name="externalReferences"
              style={{
                marginTop: 20,
                width: '100%',
              }}
              setFieldValue={setFieldValue}
              values={values.externalReferences}
          />
          <OpenVocabField
              label={t('Platforms')}
              type="platforms_ov"
              name="x_mitre_platforms"
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              multiple={true}
          />
          <OpenVocabField
              label={t('Layers')}
              type="collection_layers_ov"
              name="collection_layers"
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              multiple={true}
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
  </Formik>;
};

const DataSourceCreation: FunctionComponent<DataSourceCreationProps> = ({
  contextual,
  display,
  inputValue,
  paginationOptions,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_dataSources',
    paginationOptions,
    'dataSourceAdd',
  );

  const renderClassic = () => (
    <div>
      <Fab onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}>
        <Add />
      </Fab>
      <Drawer open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}>
        <div className={classes.header}>
          <IconButton aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
            color="primary">
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create a data source')}</Typography>
        </div>
        <div className={classes.container}>
          <DataSourceCreationForm inputValue={inputValue} updater={updater}
                                  onCompleted={handleClose} onReset={handleClose}/>
        </div>
      </Drawer>
    </div>
  );

  const renderContextual = () => (
    <div style={{ display: display ? 'block' : 'none' }}>
      <Fab onClick={handleOpen} color="secondary" aria-label="Add"
        className={classes.createButtonContextual}>
        <Add />
      </Fab>
      <Dialog open={open} onClose={handleClose} PaperProps={{ elevation: 1 }}>
        <DialogTitle>{t('Create a data source')}</DialogTitle>
        <DialogContent>
          <DataSourceCreationForm inputValue={inputValue} updater={updater}
                                 onCompleted={handleClose} onReset={handleClose}/>
        </DialogContent>
      </Dialog>
    </div>
  );

  if (contextual) {
    return renderContextual();
  }
  return renderClassic();
};

export default DataSourceCreation;
