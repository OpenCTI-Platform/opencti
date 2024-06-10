import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { MoreVertOutlined } from '@mui/icons-material';
import MenuItem from '@mui/material/MenuItem';
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
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import LabelsVocabulariesMenu from '../LabelsVocabulariesMenu';
import { CaseTemplateTasksLine_node$data } from './__generated__/CaseTemplateTasksLine_node.graphql';
import { CaseTemplateTasksLines_DataQuery$variables } from './__generated__/CaseTemplateTasksLines_DataQuery.graphql';
import { CaseTemplateTasksLinesPaginationQuery, CaseTemplateTasksLinesPaginationQuery$variables } from './__generated__/CaseTemplateTasksLinesPaginationQuery.graphql';
import CaseTemplateTasksLines, { tasksLinesQuery } from './CaseTemplateTasksLines';
import { CaseTemplateEditionQuery } from './__generated__/CaseTemplateEditionQuery.graphql';
import CaseTemplateEdition, { caseTemplateQuery } from './CaseTemplateEdition';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import { commitMutation } from '../../../../relay/environment';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { CaseTemplateLine_node$key } from './__generated__/CaseTemplateLine_node.graphql';
import { CaseTemplateLineFragment } from './CaseTemplateLine';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
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
  const { t_i18n } = useFormatter();
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
          color="primary"
        >
          <MoreVertOutlined />
        </IconButton>
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={handleMenuClose}
        >
          <MenuItem onClick={onUpdateClick}>{t_i18n('Update')}</MenuItem>
          <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
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
            {t_i18n('Do you want to delete this case template?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete}>{t_i18n('Cancel')}</Button>
          <Button color="secondary" onClick={submitDelete}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

const LOCAL_STORAGE_KEY = 'case-template-tasks';

const CaseTemplateTasks = () => {
  const classes = useStyles();
  const { caseTemplateId } = useParams() as { caseTemplateId: string };
  const caseTemplateQueryRef = useQueryLoading<CaseTemplateEditionQuery>(
    caseTemplateQuery,
    { id: caseTemplateId },
  );
  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage<CaseTemplateTasksLines_DataQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      sortBy: 'name',
      orderAsc: true,
      searchTerm: '',
    },
  );
  const { filters } = viewStorage;
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Case-Template']);
  const contextTaskFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'tasks', operator: 'eq', mode: 'or', values: [caseTemplateId] },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const queryTaskTemplatePaginationOptions = {
    ...paginationOptions,
    filters: contextTaskFilters,
  } as unknown as CaseTemplateTasksLinesPaginationQuery$variables;

  const CaseTemplateTasksLinesQueryRef = useQueryLoading<CaseTemplateTasksLinesPaginationQuery>(
    tasksLinesQuery,
    queryTaskTemplatePaginationOptions,
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
        isSortable: false,
        render: (node: CaseTemplateTasksLine_node$data) => node.description,
      },
    };
    return (
      <ListLines
        sortBy={viewStorage.sortBy}
        orderAsc={viewStorage.orderAsc}
        dataColumns={dataColumns}
        paginationOptions={queryTaskTemplatePaginationOptions}
        keyword={queryTaskTemplatePaginationOptions.search}
        filters={viewStorage.filters}
        handleSearch={helpers.handleSearch}
        numberOfElements={viewStorage.numberOfElements}
        handleSort={helpers.handleSort}
        secondaryAction
      >
        {CaseTemplateTasksLinesQueryRef && (
          <>
            <React.Suspense
              fallback={<Loader variant={LoaderVariant.inElement} />}
            >
              <CaseTemplateTasksLines
                queryRef={CaseTemplateTasksLinesQueryRef}
                paginationOptions={queryTaskTemplatePaginationOptions}
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
              paginationOptions={queryTaskTemplatePaginationOptions}
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
