import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import React, { FunctionComponent, useRef } from 'react';
import { graphql, useMutation } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { deleteNode, insertNode } from '../../../../utils/store';
import CaseTemplateTasks from '../../common/form/CaseTemplateTasks';
import { Option } from '../../common/form/ReferenceField';
import { CaseTemplateLine_node$data } from './__generated__/CaseTemplateLine_node.graphql';
import { CaseTemplateTasksLines_DataQuery$variables } from './__generated__/CaseTemplateTasksLines_DataQuery.graphql';

const caseTemplateAddTask = graphql`
  mutation CaseTemplateEditionAddTaskMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    caseTemplateRelationAdd(id: $id, input: $input) {
      ...CaseTemplateLine_node
    }
  }
`;

const caseTemplateDeleteTask = graphql`
  mutation CaseTemplateEditionDeleteTaskMutation($id: ID!, $toId: StixRef!) {
    caseTemplateRelationDelete(
      id: $id
      toId: $toId
      relationship_type: "template-task"
    ) {
      id
    }
  }
`;

export const caseTemplateQuery = graphql`
  query CaseTemplateEditionQuery($id: String!) {
    caseTemplate(id: $id) {
      ...CaseTemplateLine_node
    }
  }
`;

export const caseTemplateFieldPatch = graphql`
  mutation CaseTemplateEditionMutation($id: ID!, $input: [EditInput!]!) {
    caseTemplateFieldPatch(id: $id, input: $input) {
      id
      ...CaseTemplateLine_node
    }
  }
`;

interface CaseTemplateEditionProps {
  caseTemplate: CaseTemplateLine_node$data;
  paginationOptions: CaseTemplateTasksLines_DataQuery$variables;
  openPanel: boolean;
  setOpenPanel: (status: boolean) => void;
}

const caseTemplateValidation = (t: (name: string | object) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  tasks: Yup.array(),
});

const CaseTemplateEdition: FunctionComponent<CaseTemplateEditionProps> = ({
  caseTemplate,
  paginationOptions,
  openPanel,
  setOpenPanel,
}) => {
  const { t } = useFormatter();
  const handleClose = () => setOpenPanel(false);

  const [commitAddTask] = useMutation(caseTemplateAddTask);
  const [commitDeleteTask] = useMutation(caseTemplateDeleteTask);
  const [commitFieldPatch] = useMutation(caseTemplateFieldPatch);

  const existingTasks = useRef<Option[] | undefined>();
  if (!existingTasks.current) {
    existingTasks.current = caseTemplate.tasks.edges.map(({ node }) => ({
      value: node.id,
      label: node.name,
    }));
  }
  const submitTaskEdition = (values: Option[]) => {
    const added = R.difference(values, existingTasks.current ?? []).at(0);
    const removed = R.difference(existingTasks.current ?? [], values).at(0);
    if (added?.value) {
      const input = { toId: added.value, relationship_type: 'template-task' };
      commitAddTask({
        variables: { id: caseTemplate.id, input },
        updater: (store: RecordSourceSelectorProxy) => insertNode(
          store,
          'Pagination_caseTemplate__taskTemplates',
          paginationOptions,
          'caseTemplateRelationAdd',
          null,
          null,
          input,
        ),
      });
    }
    if (removed?.value) {
      commitDeleteTask({
        variables: {
          id: caseTemplate.id,
          toId: removed.value,
        },
        updater: (store: RecordSourceSelectorProxy) => deleteNode(
          store,
          'Pagination_caseTemplate__taskTemplates',
          paginationOptions,
          removed.value,
        ),
      });
    }
    existingTasks.current = values;
  };

  const handleSubmitField = (name: string, value: string) => {
    commitFieldPatch({
      variables: {
        id: caseTemplate.id,
        input: [
          {
            key: name,
            value: [value],
          },
        ],
      },
    });
  };

  return (
    <Drawer
      title={t('Update the case template')}
      variant={DrawerVariant.updateWithPanel}
      open={openPanel}
      onClose={handleClose}
    >
      <Formik
        initialValues={{
          ...caseTemplate,
          tasks: existingTasks.current,
        }}
        onSubmit={() => {
        }}
        validationSchema={caseTemplateValidation(t)}
      >
        {({ values: currentValues, setFieldValue }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth
              onSubmit={handleSubmitField}
              style={{ marginBottom: '20px' }}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t('Description')}
              fullWidth
              multiline
              rows="4"
              style={fieldSpacingContainerStyle}
              onSubmit={handleSubmitField}
            />
            <CaseTemplateTasks
              onChange={(name, values) => {
                submitTaskEdition(values);
                setFieldValue(name, values);
              }}
              values={currentValues.tasks}
            />
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default CaseTemplateEdition;
