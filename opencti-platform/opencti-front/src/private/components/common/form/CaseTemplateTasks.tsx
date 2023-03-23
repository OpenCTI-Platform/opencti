import { CenterFocusStrong } from '@mui/icons-material';
import { DialogContent } from '@mui/material';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogTitle from '@mui/material/DialogTitle';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import * as R from 'ramda';
import React, { FunctionComponent, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import TextField from '../../../../components/TextField';
import { fetchQuery, handleErrorInForm } from '../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { CaseTaskAddInput, CaseTemplateTasksCreationMutation } from './__generated__/CaseTemplateTasksCreationMutation.graphql';
import { CaseTemplateTasksSearchQuery$data } from './__generated__/CaseTemplateTasksSearchQuery.graphql';
import { Option } from './ReferenceField';

const useStyles = makeStyles(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
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

interface CaseTemplateFieldProps {
  caseTemplateId?: string
  onChange: (name: string, values: Option[]) => void
  values?: readonly Option[]
}

const CaseTemplateTasksQuery = graphql`
  query CaseTemplateTasksSearchQuery($search: String) {
    caseTasks(search: $search, filters: [{ key : useAsTemplate, values: ["true"]}]) {
      edges {
        node {
          id
          name
          dueDate
          description
          status {
            id
            order
            template {
              name
              color
            }
          }
          workflowEnabled
        }
      }
    }
  }
`;

const CaseTemplateTasksCreation = graphql`
  mutation CaseTemplateTasksCreationMutation($input: CaseTaskAddInput!) {
    caseTaskAdd(input: $input) {
      id
      name
    }
  }
`;

const CaseTemplateTasks: FunctionComponent<CaseTemplateFieldProps> = ({ caseTemplateId, onChange, values }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [tasks, setTasks] = useState<Option[]>([...(values ?? [])]);
  const [openCreation, setOpenCreation] = useState(false);

  const [commitTaskCreation] = useMutation<CaseTemplateTasksCreationMutation>(CaseTemplateTasksCreation);

  const searchTasks = (event: React.ChangeEvent<HTMLInputElement>) => {
    const search = event?.target?.value ?? '';
    fetchQuery(CaseTemplateTasksQuery, { search })
      .toPromise()
      .then((data) => {
        const newTasks = (data as CaseTemplateTasksSearchQuery$data)
          ?.caseTasks
          ?.edges
          ?.map(({ node }) => ({ value: node.id, label: node.name })) ?? [];
        setTasks(R.uniq([...tasks, ...newTasks]));
      });
  };

  const submitTaskCreation: FormikConfig<CaseTaskAddInput>['onSubmit'] = (
    submitValues,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const { name, description } = submitValues;
    setSubmitting(true);
    commitTaskCreation({
      variables: { input: { name, description, useAsTemplate: true, ...(caseTemplateId ? { objects: [caseTemplateId] } : {}) } },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (data) => {
        setSubmitting(false);
        setOpenCreation(false);
        onChange('tasks', [
          ...(values ?? []),
          ...(data.caseTaskAdd ? [{ value: data.caseTaskAdd.id, label: data.caseTaskAdd.name }] : []),
        ]);
        resetForm();
      },
    });
  };

  return (
    <>
      <Field
        component={AutocompleteField}
        style={fieldSpacingContainerStyle}
        name="tasks"
        multiple={true}
        textfieldprops={{
          variant: 'standard',
          label: t('Tasks'),
          onFocus: searchTasks,
        }}
        noOptionsText={t('No available options')}
        options={tasks}
        onInputChange={searchTasks}
        onChange={onChange}
        openCreate={() => setOpenCreation(true)}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
        isOptionEqualToValue={(option: Option, value: Option) => option.value === value.value}
        renderOption={(props: React.HTMLAttributes<HTMLLIElement>, option: Option) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <CenterFocusStrong />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
      />
      <Dialog open={openCreation}>
        <Formik
          initialValues={{
            name: '',
            description: '',
          }}
          onSubmit={submitTaskCreation}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <DialogTitle>{t('Create a task')}</DialogTitle>
              <DialogContent>
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t('Name')}
                  fullWidth={true}
                />
                <Field
                  component={MarkDownField}
                  name="description"
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 20, marginBottom: 20 }}
                />
              </DialogContent>
              <DialogActions>
                <Button
                  onClick={() => {
                    handleReset();
                    setOpenCreation(false);
                  }}
                  disabled={isSubmitting}
                >
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
    </>
  );
};

export default CaseTemplateTasks;
