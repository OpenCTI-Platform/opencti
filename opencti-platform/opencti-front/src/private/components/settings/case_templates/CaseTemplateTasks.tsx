import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import React, { useState, FunctionComponent } from 'react';
import { useParams } from 'react-router-dom';
import { MoreVertOutlined } from '@mui/icons-material';
import MenuItem from '@mui/material/MenuItem';
import { useNavigate } from 'react-router-dom-v5-compat';
import { graphql, PreloadedQuery } from 'react-relay';
import Button from '@mui/material/Button';
import Menu from '@mui/material/Menu';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import IconButton from '@mui/material/IconButton';
import ListLines from '../../../../components/list_lines/ListLines';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { BackendFilters } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import LabelsVocabulariesMenu from '../LabelsVocabulariesMenu';
import { CaseTemplateTasksLine_node$data } from './__generated__/CaseTemplateTasksLine_node.graphql';
import { CaseTemplateTasksLines_DataQuery$variables } from './__generated__/CaseTemplateTasksLines_DataQuery.graphql';
import { CaseTemplateTasksLinesPaginationQuery } from './__generated__/CaseTemplateTasksLinesPaginationQuery.graphql';
import CaseTemplateTasksLines, {
  tasksLinesQuery,
} from './CaseTemplateTasksLines';
import { CaseTemplateEditionQuery } from './__generated__/CaseTemplateEditionQuery.graphql';
import CaseTemplateEdition, { caseTemplateQuery } from './CaseTemplateEdition';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import { commitMutation } from '../../../../relay/environment';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { CaseTemplateLine_node$key } from './__generated__/CaseTemplateLine_node.graphql';
import { CaseTemplateLineFragment } from './CaseTemplateLine';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  label: {
    fontSize: 12,
    height: 20,
    float: 'left',
    marginRight: 7,
  },
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  aliases: {
    marginRight: 7,
  },
  aliasesInput: {
    margin: '4px 0 0 10px',
    float: 'right',
  },
  modes: {
    margin: '-10px 0 0 0',
    float: 'right',
  },
  button: {
    marginRight: 20,
  },
  export: {
    margin: '-10px 0 0 0',
    float: 'right',
  },
}));

const caseTemplateTasksDeletionMutation = graphql`
  mutation CaseTemplateTasksDeletionMutation($id: ID!) {
    caseTemplateDelete(id: $id)
  }
`;

interface CaseHeaderMenuProps {
  queryRef: PreloadedQuery<CaseTemplateEditionQuery>;
  caseTemplateId: string;
  paginationOptions: CaseTemplateTasksLines_DataQuery$variables;
}

const CaseHeaderMenu: FunctionComponent<CaseHeaderMenuProps> = ({
  queryRef,
  caseTemplateId,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [openEdition, setOpenEdition] = useState(false);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const handleCloseDelete = () => setDisplayDelete(false);
  const handleMenuOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleMenuClose = () => {
    setAnchorEl(null);
  };
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleMenuClose();
  };
  const onUpdateClick = () => {
    setOpenEdition(true);
    handleMenuClose();
  };
  const submitDelete = () => {
    commitMutation({
      mutation: caseTemplateTasksDeletionMutation,
      variables: {
        id: caseTemplateId,
      },
      onCompleted: () => {
        handleCloseDelete();
        navigate('/dashboard/settings/vocabularies/caseTemplates');
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };
  const caseTemplate = usePreloadedFragment<
  CaseTemplateEditionQuery,
  CaseTemplateLine_node$key
  >({
    queryRef,
    fragmentDef: CaseTemplateLineFragment,
    queryDef: caseTemplateQuery,
    nodePath: 'caseTemplate',
  });
  return (
    <>
      <Typography
        variant="h1"
        gutterBottom={true}
        classes={{ root: classes.title }}
      >
        {caseTemplate.name}
      </Typography>
      <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <CaseTemplateEdition
          caseTemplate={caseTemplate}
          paginationOptions={paginationOptions}
          openPanel={openEdition}
          setOpenPanel={setOpenEdition}
        />
      </React.Suspense>
      <div className={classes.popover}>
        <IconButton
          onClick={handleMenuOpen}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
          size="large"
        >
          <MoreVertOutlined />
        </IconButton>
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={handleMenuClose}
        >
          <MenuItem onClick={onUpdateClick}>{t('Update')}</MenuItem>
          <MenuItem onClick={handleOpenDelete}>{t('Delete')}</MenuItem>
        </Menu>
      </div>
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to delete this case template?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete}>{t('Cancel')}</Button>
          <Button color="secondary" onClick={submitDelete}>
            {t('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

const CaseTemplateTasks = () => {
  const classes = useStyles();
  const { caseTemplateId } = useParams() as { caseTemplateId: string };
  const caseTemplateQueryRef = useQueryLoading<CaseTemplateEditionQuery>(
    caseTemplateQuery,
    { id: caseTemplateId },
  );
  const taskFilters: BackendFilters = [
    { key: 'taskContains', values: [caseTemplateId] },
  ];
  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage<CaseTemplateTasksLines_DataQuery$variables>(
    'view-case-template-tasks',
    {
      sortBy: 'name',
      orderAsc: true,
      searchTerm: '',
    },
    taskFilters,
  );
  const queryRef = useQueryLoading<CaseTemplateTasksLinesPaginationQuery>(
    tasksLinesQuery,
    paginationOptions,
  );
  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '25%',
        isSortable: true,
        render: (node: CaseTemplateTasksLine_node$data) => node.name,
      },
      description: {
        label: 'Description',
        width: '65%',
        isSortable: true,
        render: (node: CaseTemplateTasksLine_node$data) => node.description,
      },
    };
    return (
      <ListLines
        sortBy={viewStorage.sortBy}
        orderAsc={viewStorage.orderAsc}
        dataColumns={dataColumns}
        keyword={paginationOptions.search}
        filters={viewStorage.filters}
        handleSearch={helpers.handleSearch}
        numberOfElements={viewStorage.numberOfElements}
        handleSort={helpers.handleSort}
        secondaryAction
      >
        {queryRef && (
          <>
            <React.Suspense
              fallback={<Loader variant={LoaderVariant.inElement} />}
            >
              <CaseTemplateTasksLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={helpers.handleSetNumberOfElements}
              />
            </React.Suspense>
          </>
        )}
      </ListLines>
    );
  };
  return (
    <div className={classes.container}>
      {caseTemplateQueryRef && (
        <>
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <CaseHeaderMenu
              caseTemplateId={caseTemplateId}
              paginationOptions={paginationOptions}
              queryRef={caseTemplateQueryRef}
            />
          </React.Suspense>
        </>
      )}
      <div className="clearfix" style={{ paddingTop: 16 }} />
      <LabelsVocabulariesMenu />
      {renderLines()}
    </div>
  );
};

export default CaseTemplateTasks;
