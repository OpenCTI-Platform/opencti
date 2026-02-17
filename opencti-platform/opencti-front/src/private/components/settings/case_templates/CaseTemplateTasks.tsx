import { Box } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { useNavigate, useParams } from 'react-router-dom';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import HeaderMainEntityLayout from '../../../../components/common/header/HeaderMainEntityLayout';
import DeleteDialog from '../../../../components/DeleteDialog';
import { useFormatter } from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import PopoverMenu from '../../../../components/PopoverMenu';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import LabelsVocabulariesMenu from '../LabelsVocabulariesMenu';
import { CaseTemplateEditionQuery } from './__generated__/CaseTemplateEditionQuery.graphql';
import { CaseTemplateLine_node$key } from './__generated__/CaseTemplateLine_node.graphql';
import { CaseTemplateTasksLine_node$data } from './__generated__/CaseTemplateTasksLine_node.graphql';
import { CaseTemplateTasksLines_DataQuery$variables } from './__generated__/CaseTemplateTasksLines_DataQuery.graphql';
import { CaseTemplateTasksLinesPaginationQuery, CaseTemplateTasksLinesPaginationQuery$variables } from './__generated__/CaseTemplateTasksLinesPaginationQuery.graphql';
import CaseTemplateEdition, { caseTemplateQuery } from './CaseTemplateEdition';
import { CaseTemplateLineFragment } from './CaseTemplateLine';
import CaseTemplateTasksLines, { tasksLinesQuery } from './CaseTemplateTasksLines';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
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
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [openEdition, setOpenEdition] = useState(false);
  const [openDelete, setOpenDelete] = useState(false);
  const handleClose = () => {};

  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);

  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('CaseTemplate') },
  });
  const [commitDeleteMutation] = useApiMutation(
    caseTemplateTasksDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const deletion = useDeletion({ handleClose });
  const submitDelete = () => {
    commitDeleteMutation({
      variables: {
        id: caseTemplateId,
      },
      onCompleted: () => {
        handleCloseDelete();
        navigate('/dashboard/settings/vocabularies/case_templates');
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
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

  const breadcrumb = [
    { label: t_i18n('Settings') },
    { label: t_i18n('Taxonomies') },
    { label: t_i18n('Case templates'), link: '/dashboard/settings/vocabularies/case_templates' },
    { label: caseTemplate.name, current: true },
  ];

  return (
    <>
      <Breadcrumbs elements={breadcrumb} />

      <HeaderMainEntityLayout
        title={caseTemplate.name}
        rightActions={(
          <>
            <PopoverMenu>
              {({ closeMenu }) => (
                <Box>
                  <MenuItem onClick={() => {
                    handleOpenDelete();
                    closeMenu();
                  }}
                  >
                    {t_i18n('Delete')}
                  </MenuItem>
                </Box>
              )}
            </PopoverMenu>
            <CaseTemplateEdition
              caseTemplate={caseTemplate}
              paginationOptions={paginationOptions}
              openPanel={openEdition}
              setOpenPanel={setOpenEdition}
            />
            <DeleteDialog
              deletion={deletion}
              isOpen={openDelete}
              onClose={handleCloseDelete}
              submitDelete={submitDelete}
              message={t_i18n('Do you want to delete this template?')}
            />
          </>
        )}
      />
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
        iconExtension
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
      <LabelsVocabulariesMenu />
      {renderLines()}
    </div>
  );
};

export default CaseTemplateTasks;
