import { Add, Close, ContentPasteGoOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import Paper from '@mui/material/Paper';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Form, Formik } from 'formik';
import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, useMutation } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import { Theme } from '../../../components/Theme';
import { handleErrorInForm } from '../../../relay/environment';
import usePreloadedPaginationFragment from '../../../utils/hooks/usePreloadedPaginationFragment';
import CaseTemplateField from '../common/form/CaseTemplateField';
import { Option } from '../common/form/ReferenceField';
import { CaseTasksLines_data$key } from './__generated__/CaseTasksLines_data.graphql';
import {
  CaseTasksLinesQuery,
  CaseTasksLinesQuery$variables,
} from './__generated__/CaseTasksLinesQuery.graphql';
import { CaseTasksFiltering } from './__generated__/CaseTasksRefetch.graphql';
import CaseTaskCreation from './case_task/CaseTaskCreation';
import CaseTasksLineTitles from './case_task/CaseTasksLineTitles';
import CaseTasksLine from './CaseTasksLine';
import { caseSetTemplateQuery, generateConnectionId } from './CaseUtils';

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
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-5px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  createButton: {
    float: 'left',
    marginTop: -15,
  },
  applyButton: {
    float: 'right',
    marginTop: -15,
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
  title: {
    float: 'left',
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  emptyContainer: {
    display: 'table',
    height: '100%',
    width: '100%',
    paddingTop: 15,
    paddingBottom: 15,
  },
  emptySpan: {
    display: 'table-cell',
    verticalAlign: 'middle',
    textAlign: 'center',
  },
}));

export const caseTasksLinesQuery = graphql`
  query CaseTasksLinesQuery(
    $count: Int
    $filters: [CaseTasksFiltering!]
    $cursor: ID
  ) {
    ...CaseTasksLines_data
      @arguments(count: $count, filters: $filters, cursor: $cursor)
  }
`;

const caseTasksLinesFragment = graphql`
  fragment CaseTasksLines_data on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 25 }
    filters: { type: "[CaseTasksFiltering!]" }
    cursor: { type: "ID" }
  )
  @refetchable(queryName: "CaseTasksRefetch") {
    caseTasks(first: $count, filters: $filters, after: $cursor)
      @connection(key: "Pagination_caseTasks") {
      edges {
        node {
          ...CaseTasksLine_data
        }
      }
    }
  }
`;

interface CaseTasksLinesProps {
  caseId: string;
  queryRef: PreloadedQuery<CaseTasksLinesQuery>;
  paginationOptions: CaseTasksLinesQuery$variables;
  tasksFilters: { filters: CaseTasksFiltering[] };
  defaultMarkings?: Option[];
}

const CaseTasksLines: FunctionComponent<CaseTasksLinesProps> = ({
  caseId,
  queryRef,
  paginationOptions,
  tasksFilters,
  defaultMarkings,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const [openCaseTemplate, setOpenCaseTemplate] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const [commit] = useMutation(caseSetTemplateQuery);
  const { data } = usePreloadedPaginationFragment<
  CaseTasksLinesQuery,
  CaseTasksLines_data$key
  >({
    queryRef,
    linesQuery: caseTasksLinesQuery,
    linesFragment: caseTasksLinesFragment,
  });
  return (
    <div style={{ height: '100%' }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{ float: 'left', paddingBottom: 11 }}
      >
        {t('Tasks')}
      </Typography>
      <Tooltip title={t('Add a task to this container')}>
        <IconButton
          color="secondary"
          aria-label="Add"
          onClick={handleOpen}
          classes={{ root: classes.createButton }}
          size="large"
        >
          <Add fontSize="small" />
        </IconButton>
      </Tooltip>
      <>
        <Tooltip title={t('Apply a new case template')}>
          <IconButton
            color="primary"
            aria-label="Apply"
            onClick={() => setOpenCaseTemplate(true)}
            classes={{ root: classes.applyButton }}
            size="large"
          >
            <ContentPasteGoOutlined fontSize="small" />
          </IconButton>
        </Tooltip>
        <Dialog
          open={openCaseTemplate}
          onClose={() => setOpenCaseTemplate(false)}
        >
          <DialogTitle>{t('Apply case templates')}</DialogTitle>
          <DialogContent>
            <Formik
              initialValues={{ caseTemplates: [] }}
              onSubmit={(values, { setSubmitting, setErrors }) => {
                commit({
                  variables: {
                    id: caseId,
                    caseTemplatesId: values.caseTemplates.map(
                      ({ value }) => value,
                    ),
                    connections: [
                      generateConnectionId({
                        key: 'Pagination_caseTasks',
                        params: tasksFilters,
                      }),
                    ],
                  },
                  onCompleted: () => {
                    setSubmitting(false);
                    setOpenCaseTemplate(false);
                  },
                  onError: (error: Error) => {
                    handleErrorInForm(error, setErrors);
                    setSubmitting(false);
                  },
                });
              }}
            >
              {({ setFieldValue, submitForm, handleReset, isSubmitting }) => (
                <Form>
                  <CaseTemplateField
                    onChange={setFieldValue}
                    label="Case templates"
                  />
                  <div className={classes.buttons}>
                    <Button
                      onClick={() => {
                        handleReset();
                        setOpenCaseTemplate(false);
                      }}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      color="secondary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Apply')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </DialogContent>
        </Dialog>
      </>
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
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Create a task')}
          </Typography>
        </div>
        <div className={classes.container}>
          <CaseTaskCreation
            caseId={caseId}
            onClose={handleClose}
            paginationOptions={paginationOptions}
            defaultMarkings={defaultMarkings}
          />
        </div>
      </Drawer>
      <div className="clearfix" />
      <Paper classes={{ root: classes.paper }} variant="outlined">
        {data.caseTasks && data.caseTasks.edges.length > 0 ? (
          <div>
            <CaseTasksLineTitles />
            <List style={{ paddingTop: 0 }}>
              {data.caseTasks.edges.map(({ node }) => {
                return (
                  <CaseTasksLine
                    key={JSON.stringify(node)}
                    data={node}
                    paginationOptions={paginationOptions}
                    caseId={caseId}
                  />
                );
              })}
            </List>
          </div>
        ) : (
          <div className={classes.emptyContainer}>
            <span className={classes.emptySpan}>
              {t('No tasks has been found.')}
            </span>
          </div>
        )}
      </Paper>
    </div>
  );
};

export default CaseTasksLines;
