import React, { FunctionComponent } from 'react';
import { graphql, useMutation } from 'react-relay';
import { v4 as uuid } from 'uuid';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import TextField from '../../../../../components/TextField';
import AutocompleteFreeSoloField from '../../../../../components/AutocompleteFreeSoloField';
import ItemIcon from '../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../components/i18n';
import { Theme } from '../../../../../components/Theme';
import { Option } from '../../form/ReferenceField';
import { WorkbenchFileViewer_entity$data } from './__generated__/WorkbenchFileViewer_entity.graphql';
import { WorkbenchFileCreatorMutation } from './__generated__/WorkbenchFileCreatorMutation.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
}));

const workbenchFileCreatorMutation = graphql`
  mutation WorkbenchFileCreatorMutation($file: Upload!, $labels: [String], $entityId: String) {
    uploadPending(file: $file, labels: $labels, errorOnExisting: true, entityId: $entityId) {
      id
      ...FileLine_file
    }
  }
`;

const fileValidation = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
});

interface WorkbenchFileCreatorFormValues {
  name: string;
  labels: Option[];
}

interface WorkbenchFileCreatorProps {
  openCreate: boolean;
  handleCloseCreate: () => void;
  onCompleted?: () => void;
  entity?: WorkbenchFileViewer_entity$data;
}

const WorkbenchFileCreator: FunctionComponent<WorkbenchFileCreatorProps> = ({ openCreate, handleCloseCreate, onCompleted, entity }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [commitWorkbench] = useMutation<WorkbenchFileCreatorMutation>(workbenchFileCreatorMutation);
  const entityId = entity?.id;
  const onSubmitCreate: FormikConfig<WorkbenchFileCreatorFormValues>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    let { name } = values;
    const finalLabels = values.labels.map((label) => label.value);
    if (!name.endsWith('.json')) {
      name += '.json';
    }
    const objects = [];
    if (entity?.toStix) {
      const stixEntity = JSON.parse(entity.toStix);
      delete stixEntity.extensions;
      stixEntity.x_opencti_id = entity.id;
      objects.push(stixEntity);
    }
    const data = { id: `bundle--${uuid()}`, type: 'bundle', objects };
    const json = JSON.stringify(data);
    const blob = new Blob([json], { type: 'text/json' });
    const file = new File([blob], name, {
      type: 'application/json',
    });

    commitWorkbench({
      variables: { file, labels: finalLabels, entityId },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseCreate();
        onCompleted?.();
      },
    });
  };

  const initialValues: WorkbenchFileCreatorFormValues = {
    name: '',
    labels: [],
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={fileValidation(t)}
      onSubmit={onSubmitCreate}
      onReset={handleCloseCreate}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form>
          <Dialog
            PaperProps={{ elevation: 1 }}
            open={openCreate}
            onClose={handleCloseCreate}
            fullWidth
          >
            <DialogTitle>{t('Create a workbench')}</DialogTitle>
            <DialogContent>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth
              />
              <Field
                component={AutocompleteFreeSoloField}
                style={{ marginTop: 20 }}
                name="labels"
                multiple
                textfieldprops={{
                  variant: 'standard',
                  label: t('Labels'),
                }}
                options={[]}
                renderOption={(props: React.HTMLAttributes<HTMLLIElement>, option: Option) => (
                  <li {...props}>
                    <div className={classes.icon}>
                      <ItemIcon type="Label" />
                    </div>
                    <div className={classes.text}>{option.label}</div>
                  </li>
                )}
                classes={{
                  clearIndicator: classes.autoCompleteIndicator,
                }}
              />
            </DialogContent>
            <DialogActions>
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t('Cancel')}
              </Button>
              <Button
                type="submit"
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t('Create')}
              </Button>
            </DialogActions>
          </Dialog>
        </Form>
      )}
    </Formik>
  );
};

export default WorkbenchFileCreator;
