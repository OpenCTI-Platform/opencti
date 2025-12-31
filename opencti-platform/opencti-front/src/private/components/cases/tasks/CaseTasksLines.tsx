import { AddOutlined, ContentPasteGoOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import IconButton from '@common/button/IconButton';
import Paper from '@mui/material/Paper';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Form, Formik } from 'formik';
import React, { FunctionComponent, MutableRefObject, useState } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { GridTypeMap } from '@mui/material';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { handleErrorInForm } from '../../../../relay/environment';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import CaseTemplateField from '../../common/form/CaseTemplateField';
import CaseTaskCreation from './CaseTaskCreation';
import { caseSetTemplateQuery, generateConnectionId } from '../CaseUtils';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import ListLines from '../../../../components/list_lines/ListLines';
import { CaseTasksLine } from './CaseTasksLine';
import { tasksDataColumns } from './TasksLine';
import { CaseTasksLines_data$key } from './__generated__/CaseTasksLines_data.graphql';
import { CaseTasksLinesQuery, CaseTasksLinesQuery$variables } from './__generated__/CaseTasksLinesQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { FieldOption } from '../../../../utils/field';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    margin: '-5px 0 0 0',
    padding: 0,
    borderRadius: 4,
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
    $filters: FilterGroup
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
    filters: { type: "FilterGroup" }
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
  defaultMarkings?: FieldOption[];
  sortBy: string | undefined;
  orderAsc: boolean | undefined;
  handleSort?: (field: string, order: boolean) => void;
  containerRef: MutableRefObject<GridTypeMap | null>;
  enableReferences: boolean;
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
  enableReferences,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [openCaseTemplate, setOpenCaseTemplate] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const [commit] = useApiMutation(caseSetTemplateQuery);
  const { data } = usePreloadedPaginationFragment<CaseTasksLinesQuery,
    CaseTasksLines_data$key>({
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
        {t_i18n('Tasks')}
      </Typography>
      <Tooltip title={t_i18n('Add a task to this container')}>
        <IconButton
          color="primary"
          aria-label="Add"
          onClick={handleOpen}
          classes={{ root: classes.createButton }}
        >
          <AddOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
      <Tooltip title={t_i18n('Apply a new case template')}>
        <IconButton
          color="primary"
          aria-label="Apply"
          onClick={() => setOpenCaseTemplate(true)}
          classes={{ root: classes.applyButton }}
        >
          <ContentPasteGoOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={openCaseTemplate}
        onClose={() => setOpenCaseTemplate(false)}
        fullWidth={true}
        maxWidth="md"
      >
        <DialogTitle>{t_i18n('Apply case templates')}</DialogTitle>
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
                    variant="secondary"
                    onClick={() => {
                      handleReset();
                      setOpenCaseTemplate(false);
                    }}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t_i18n('Apply')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        </DialogContent>
      </Dialog>
      <Drawer
        open={open}
        title={t_i18n('Create a task')}
        onClose={handleClose}
      >
        <CaseTaskCreation
          caseId={caseId}
          onClose={handleClose}
          paginationOptions={paginationOptions}
          defaultMarkings={defaultMarkings}
        />
      </Drawer>
      <div className="clearfix" />
      <Paper classes={{ root: classes.paper }} className="paper-for-grid" variant="outlined">
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
            enableReferences={enableReferences}
          />
        </ListLines>
      </Paper>
    </div>
  );
};

export default CaseTasksLines;
