import { Close, Edit } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Formik } from 'formik';
import * as R from 'ramda';
import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, useMutation } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import TextField from '../../../../components/TextField';
import { Theme } from '../../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { deleteNode, insertNode } from '../../../../utils/store';
import CaseTemplateTasks from '../../common/form/CaseTemplateTasks';
import { Option } from '../../common/form/ReferenceField';
import { CaseTemplateEditionQuery } from './__generated__/CaseTemplateEditionQuery.graphql';
import { CaseTemplateLine_node$key } from './__generated__/CaseTemplateLine_node.graphql';
import { CaseTemplateTasksLines_DataQuery$variables } from './__generated__/CaseTemplateTasksLines_DataQuery.graphql';
import { CaseTemplateLineFragment } from './CaseTemplateLine';

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

const caseTemplateAddTask = graphql`
  mutation CaseTemplateEditionAddTaskMutation($id: ID!, $input: StixRefRelationshipAddInput!) {
    stixDomainObjectEdit(id: $id) {
      relationAdd(input: $input) {
        id
        from {
          ...CaseTemplateTasksLine_node
        }
      }
    }
  }
`;

const caseTemplateDeleteTask = graphql`
  mutation CaseTemplateEditionDeleteTaskMutation($id: ID!, $toId: StixRef!) {
    stixDomainObjectEdit(id: $id) {
      relationDelete(
        toId: $toId,
        relationship_type: "object"
      ) {
        id
      }
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
  mutation CaseTemplateEditionMutation($id: ID!, $input: [EditInput!]!){
    caseTemplateFieldPatch(id: $id, input: $input) {
      id
      ...CaseTemplateLine_node
    }
  }
`;

interface CaseTempateEditionProps {
  existingTasks: Option[]
  paginationOptions: CaseTemplateTasksLines_DataQuery$variables
  queryRef: PreloadedQuery<CaseTemplateEditionQuery>
}

const caseTemplateValidation = (t: (name: string | object) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  tasks: Yup.array(),
});

const CaseTemplateEdition: FunctionComponent<CaseTempateEditionProps> = ({
  existingTasks,
  paginationOptions,
  queryRef,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  const [commitAddTask] = useMutation(caseTemplateAddTask);
  const [commitDeleteTask] = useMutation(caseTemplateDeleteTask);
  const [commitFieldPatch] = useMutation(caseTemplateFieldPatch);

  const caseTemplate = usePreloadedFragment<CaseTemplateEditionQuery, CaseTemplateLine_node$key>({
    queryRef,
    fragmentDef: CaseTemplateLineFragment,
    queryDef: caseTemplateQuery,
    nodePath: 'caseTemplate',
  });

  const submitTaskEdition = (values: Option[]) => {
    const added = R.difference(values, existingTasks).at(0);
    const removed = R.difference(existingTasks, values).at(0);
    if (added?.value) {
      const input = {
        toId: caseTemplate.id,
        relationship_type: 'object',
      };
      commitAddTask({
        variables: {
          id: added.value,
          input,
        },
        updater: (store: RecordSourceSelectorProxy) => insertNode(
          store,
          'Pagination_caseTemplate__caseTasks',
          paginationOptions,
          'stixDomainObjectEdit',
          null,
          'relationAdd',
          input,
          'from',
        ),
      });
    }
    if (removed?.value) {
      commitDeleteTask({
        variables: {
          id: removed.value,
          toId: caseTemplate.id,
        },
        updater: (store: RecordSourceSelectorProxy) => deleteNode(
          store,
          'Pagination_caseTemplate__caseTasks',
          paginationOptions,
          removed.value,
        ),
      });
    }
  };

  const handleSubmitField = (name: string, value: string) => {
    commitFieldPatch({
      variables: {
        id: caseTemplate.id,
        input: [{
          key: name,
          value: [value],
        }],
      },
    });
  };

  return (
    <div>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Edit"
        className={classes.createButton}
      >
        <Edit />
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
          <Typography variant="h6">{t('Update the case template')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik
            initialValues={{
              ...caseTemplate,
              tasks: existingTasks,
            }}
            onSubmit={() => {}}
            validationSchema={caseTemplateValidation(t)}
          >
            {({ values: currentValues, setFieldValue }) => (
              <>
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
                  component={MarkDownField}
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
              </>
            )}
          </Formik>
        </div>
      </Drawer>
    </div>
  );
};

export default CaseTemplateEdition;
