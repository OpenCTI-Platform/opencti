import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { v4 as uuid } from 'uuid';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import makeStyles from '@mui/styles/makeStyles';
import { WorkbenchFileCreatorStixCoreObjectQuery$data } from '@components/common/files/workbench/__generated__/WorkbenchFileCreatorStixCoreObjectQuery.graphql';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import TextField from '../../../../../components/TextField';
import AutocompleteFreeSoloField from '../../../../../components/AutocompleteFreeSoloField';
import ItemIcon from '../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { WorkbenchFileViewer_entity$data } from './__generated__/WorkbenchFileViewer_entity.graphql';
import { WorkbenchFileCreatorMutation } from './__generated__/WorkbenchFileCreatorMutation.graphql';
import { fetchQuery } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../utils/field';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
  mutation WorkbenchFileCreatorMutation(
    $file: Upload!
    $labels: [String]
    $file_markings: [String!]
    $entityId: String
  ) {
    uploadPending(
      file: $file
      labels: $labels
      file_markings: $file_markings
      errorOnExisting: true
      entityId: $entityId
    ) {
      id
      ...FileLine_file
    }
  }
`;

const fileValidation = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().trim().required(t('This field is required')),
});

interface WorkbenchFileCreatorFormValues {
  name: string;
  labels: FieldOption[];
  fileMarkings: FieldOption[];
}

interface WorkbenchFileCreatorProps {
  openCreate: boolean;
  handleCloseCreate: () => void;
  onCompleted?: () => void;
  entity?: WorkbenchFileViewer_entity$data;
}

export const workbenchFileCreatorStixCoreObjectQuery = graphql`
  query WorkbenchFileCreatorStixCoreObjectQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      toStix
    }
  }
`;

const WorkbenchFileCreator: FunctionComponent<WorkbenchFileCreatorProps> = ({
  openCreate,
  handleCloseCreate,
  onCompleted,
  entity,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [commitWorkbench] = useApiMutation<WorkbenchFileCreatorMutation>(
    workbenchFileCreatorMutation,
    undefined,
  );
  const entityId = entity?.id;
  const onSubmitCreate: FormikConfig<WorkbenchFileCreatorFormValues>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    let { name } = values;
    const finalLabels = values.labels.map((label) => label.value);
    const file_markings = values.fileMarkings.map(({ value }) => value);
    if (!name.endsWith('.json')) {
      name += '.json';
    }

    const handleCompleted = () => {
      setSubmitting(false);
      resetForm();
      handleCloseCreate();
      onCompleted?.();
    };

    const handleError = () => {
      setSubmitting(false);
      resetForm();
      handleCloseCreate();
    };

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const objects: any = [];
    if (entityId) {
      fetchQuery(workbenchFileCreatorStixCoreObjectQuery, { id: entityId }).toPromise()
        .then(async (entityData) => {
          const { stixCoreObject: workbenchStixCoreObject } = entityData as WorkbenchFileCreatorStixCoreObjectQuery$data;
          if (workbenchStixCoreObject?.toStix) {
            const stixEntity = JSON.parse(workbenchStixCoreObject.toStix);
            delete stixEntity.extensions;
            stixEntity.x_opencti_id = workbenchStixCoreObject.id;
            objects.push(stixEntity);
          }
          const data = { id: `bundle--${uuid()}`, type: 'bundle', objects };
          const json = JSON.stringify(data);
          const blob = new Blob([json], { type: 'text/json' });
          const file = new File([blob], name, {
            type: 'application/json',
          });
          commitWorkbench({
            variables: { file, labels: finalLabels, entityId, file_markings },
            onCompleted: () => {
              handleCompleted();
            },
            onError: () => {
              handleError();
            },
          });
        });
    } else {
      const data = { id: `bundle--${uuid()}`, type: 'bundle', objects };
      const json = JSON.stringify(data);
      const blob = new Blob([json], { type: 'text/json' });
      const file = new File([blob], name, {
        type: 'application/json',
      });
      commitWorkbench({
        variables: { file, labels: finalLabels, entityId, file_markings },
        onCompleted: () => {
          handleCompleted();
        },
        onError: () => {
          handleError();
        },
      });
    }
  };

  const initialValues: WorkbenchFileCreatorFormValues = {
    name: '',
    labels: [],
    fileMarkings: [],
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={fileValidation(t_i18n)}
      onSubmit={onSubmitCreate}
      onReset={handleCloseCreate}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
        <Form>
          <Dialog
            slotProps={{ paper: { elevation: 1 } }}
            open={openCreate}
            onClose={handleCloseCreate}
            fullWidth
          >
            <DialogTitle>{t_i18n('Create a workbench')}</DialogTitle>
            <DialogContent>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth
              />
              <Field
                component={AutocompleteFreeSoloField}
                style={{ marginTop: 20 }}
                name="labels"
                multiple
                textfieldprops={{
                  variant: 'standard',
                  label: t_i18n('Labels'),
                }}
                options={[]}
                renderOption={(
                  props: React.HTMLAttributes<HTMLLIElement>,
                  option: FieldOption,
                ) => (
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
              <ObjectMarkingField
                name="fileMarkings"
                label={t_i18n('File marking definition levels')}
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
                required={false}
              />
            </DialogContent>
            <DialogActions>
              <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button
                type="submit"
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('Create')}
              </Button>
            </DialogActions>
          </Dialog>
        </Form>
      )}
    </Formik>
  );
};

export default WorkbenchFileCreator;
