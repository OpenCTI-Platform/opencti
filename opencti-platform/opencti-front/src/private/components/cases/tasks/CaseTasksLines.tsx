import {
  AddOutlined,
  CloseOutlined,
  ContentPasteGoOutlined,
} from '@mui/icons-material';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Paper from '@mui/material/Paper';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Form, Formik } from 'formik';
import React, { FunctionComponent, MutableRefObject, useState } from 'react';
import { graphql, PreloadedQuery, useMutation } from 'react-relay';
import { GridTypeMap } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { handleErrorInForm } from '../../../../relay/environment';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import CaseTemplateField from '../../common/form/CaseTemplateField';
import { Option } from '../../common/form/ReferenceField';
import CaseTaskCreation from './CaseTaskCreation';
import { caseSetTemplateQuery, generateConnectionId } from '../CaseUtils';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import ListLines from '../../../../components/list_lines/ListLines';
import { CaseTasksLine } from './CaseTasksLine';
import { tasksDataColumns } from './TasksLine';
import { CaseTasksLines_data$key } from './__generated__/CaseTasksLines_data.graphql';
import {
  CaseTasksLinesQuery,
  CaseTasksLinesQuery$variables,
} from './__generated__/CaseTasksLinesQuery.graphql';

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
    overflowY: 'inherit',
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
}));

export const caseTasksLinesQuery = graphql`
  query CaseTasksLinesQuery(
    $count: Int
    $filters: [TasksFiltering!]
    $cursor: ID
    $orderBy: TasksOrdering
    $orderMode: OrderingMode
  ) {
    ...CaseTasksLines_data
      @arguments(
        count: $count
        filters: $filters
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const caseTasksLinesFragment = graphql`
  fragment CaseTasksLines_data on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 25 }
    filters: { type: "[TasksFiltering!]" }
    cursor: { type: "ID" }
    orderBy: { type: "TasksOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
  )
  @refetchable(queryName: "TasksRefetch") {
    tasks(
      first: $count
      filters: $filters
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_tasks") {
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
  defaultMarkings?: Option[];
  sortBy: string | undefined;
  orderAsc: boolean | undefined;
  handleSort?: (field: string, order: boolean) => void;
  containerRef: MutableRefObject<GridTypeMap | null>;
}

const CaseTasksLines: FunctionComponent<CaseTasksLinesProps> = ({
  caseId,
  queryRef,
  paginationOptions,
  defaultMarkings,
  sortBy,
  orderAsc,
  handleSort,
  containerRef,
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
  const { count: _, ...tasksFilters } = paginationOptions;
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
          <AddOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
      <Tooltip title={t('Apply a new case template')}>
        <IconButton
          color="secondary"
          aria-label="Apply"
          onClick={() => setOpenCaseTemplate(true)}
          classes={{ root: classes.applyButton }}
          size="large"
        >
          <ContentPasteGoOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={openCaseTemplate}
        onClose={() => setOpenCaseTemplate(false)}
        fullWidth={true}
        maxWidth="md"
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
                      key: 'Pagination_tasks',
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
              <Form style={{ minWidth: 400 }}>
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
            <CloseOutlined fontSize="small" color="primary" />
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
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          handleSort={handleSort}
          dataColumns={tasksDataColumns}
          inline={true}
          secondaryAction={true}
        >
          <ListLinesContent
            dataColumns={tasksDataColumns}
            dataList={data?.tasks?.edges ?? []}
            LineComponent={CaseTasksLine}
            isLoading={() => false}
            entityId={caseId}
            paginationOptions={tasksFilters}
            containerRef={containerRef}
          />
        </ListLines>
      </Paper>
    </div>
  );
};

export default CaseTasksLines;
