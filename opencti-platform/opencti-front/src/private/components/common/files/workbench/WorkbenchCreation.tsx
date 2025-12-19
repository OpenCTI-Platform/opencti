import React from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { FormikConfig } from 'formik/dist/types';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { WorkbenchCreationMutation } from '@components/common/files/workbench/__generated__/WorkbenchCreationMutation.graphql';
import { useTheme } from '@mui/styles';
import { WorkbenchFileCreatorStixCoreObjectQuery$data } from '@components/common/files/workbench/__generated__/WorkbenchFileCreatorStixCoreObjectQuery.graphql';
import { v4 as uuid } from 'uuid';
import { workbenchFileCreatorStixCoreObjectQuery } from '@components/common/files/workbench/WorkbenchFileCreator';
import { ImportWorkbenchesContentQuery$variables } from '@components/data/import/__generated__/ImportWorkbenchesContentQuery.graphql';
import { insertNode } from '../../../../../utils/store';
import { fetchQuery } from '../../../../../relay/environment';
import TextField from '../../../../../components/TextField';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import AutocompleteFreeSoloField from '../../../../../components/AutocompleteFreeSoloField';
import ItemIcon from '../../../../../components/ItemIcon';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../utils/field';
import type { Theme } from '../../../../../components/Theme';
import CreateEntityControlledDial from '../../../../../components/CreateEntityControlledDial';

const workbenchCreationMutation = graphql`
  mutation WorkbenchCreationMutation(
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

interface WorkbenchCreationProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  paginationOptions: ImportWorkbenchesContentQuery$variables;
  entity?: { id: string };
}

interface WorkbenchFileFormValues {
  name: string;
  labels: FieldOption[];
  fileMarkings: FieldOption[];
}

const WorkbenchCreationForm: React.FC<WorkbenchCreationProps> = ({ onCompleted, onReset, entity, paginationOptions }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [commitMutation] = useApiMutation<WorkbenchCreationMutation>(workbenchCreationMutation);

  const entityId = entity?.id;
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_global_pendingFiles',
    paginationOptions,
    'uploadPending',
  );

  const fileValidation = () => Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
  });

  const onSubmit: FormikConfig<WorkbenchFileFormValues>['onSubmit'] = (values, {
    setSubmitting,
    setErrors,
    resetForm,
  }) => {
    let { name } = values;
    const finalLabels = values.labels.map((label) => label.value);
    const file_markings = values.fileMarkings.map(({ value }) => value);
    if (!name.endsWith('.json')) {
      name += '.json';
    }

    const handleCompleted = () => {
      setSubmitting(false);
      resetForm();
      onCompleted?.();
    };

    const handleError = (error: Error) => {
      setErrors(error);
      setSubmitting(false);
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
          commitMutation({
            variables: { file, labels: finalLabels, entityId, file_markings },
            updater: (store) => {
              updater(store);
            },
            onCompleted: () => {
              handleCompleted();
            },
            onError: (error: Error) => {
              handleError(error);
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
      commitMutation({
        variables: { file, labels: finalLabels, entityId, file_markings },
        updater: (store) => {
          updater(store);
        },
        onCompleted: () => {
          handleCompleted();
        },
        onError: (error: Error) => {
          handleError(error);
        },
      });
    }
  };

  const initialValues = {
    name: '',
    labels: [],
    fileMarkings: [],
  } as WorkbenchFileFormValues;

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={fileValidation}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth
            askIa
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
                <div style={{
                  paddingTop: 4,
                  display: 'inline-block',
                  color: theme.palette.primary.main,
                }}
                >
                  <ItemIcon type="Label" />
                </div>
                <div style={{
                  display: 'inline-block',
                  flexGrow: 1,
                  marginLeft: 10,
                }}
                >
                  {option.label}
                </div>
              </li>
            )}
            classes={{
              clearIndicator: {
                display: 'none',
              },
            }}
          />
          <ObjectMarkingField
            name="fileMarkings"
            label={t_i18n('File marking definition levels')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            required={false}
          />
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: 10 }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
              style={{ marginLeft: 10 }}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

const WorkbenchCreation = ({
  entity,
  paginationOptions,
}: {
  entity?: { id: string };
  paginationOptions: ImportWorkbenchesContentQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_uploadedFiles', paginationOptions, 'uploadPending');
  const CreateWorkbenchControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Workbench" {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a workbench')}
      controlledDial={CreateWorkbenchControlledDial}
    >
      {({ onClose }) => (
        <WorkbenchCreationForm
          updater={updater}
          entity={entity}
          onCompleted={onClose}
          onReset={onClose}
          paginationOptions={paginationOptions}
        />
      )}
    </Drawer>
  );
};

export default WorkbenchCreation;
