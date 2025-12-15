import React, { FunctionComponent, useState } from 'react';
import { graphql, useQueryLoader } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import makeStyles from '@mui/styles/makeStyles';
import { FormLinesPaginationQuery$variables } from '@components/data/forms/__generated__/FormLinesPaginationQuery.graphql';
import { ConnectionHandler } from 'relay-runtime';
import { FormEditionContainerQuery } from './__generated__/FormEditionContainerQuery.graphql';
import FormEditionContainer, { formEditionContainerQuery } from './FormEditionContainer';
import { FormCreationContainer } from './FormCreationContainer';
import { useFormatter } from '../../../../components/i18n';
import { deleteNode } from '../../../../utils/store';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import handleExportJson from './FormExportHandler';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const formPopoverDeletionMutation = graphql`
  mutation FormPopoverDeletionMutation($id: ID!) {
    formDelete(id: $id)
  }
`;

interface FormPopoverProps {
  formId: string;
  paginationOptions: FormLinesPaginationQuery$variables;
  formName?: string;
}

const FormPopover: FunctionComponent<FormPopoverProps> = ({
  formId,
  paginationOptions,
  formName = '',
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);

  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  // -- Edition --
  const [queryRef, loadQuery] = useQueryLoader<FormEditionContainerQuery>(formEditionContainerQuery);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    loadQuery({ id: formId });
    handleClose();
  };

  // -- Duplicate --
  const [displayDuplicate, setDisplayDuplicate] = useState<boolean>(false);
  const handleOpenDuplicate = () => {
    setDisplayDuplicate(true);
    loadQuery({ id: formId });
    handleClose();
  };

  // -- Export --
  const handleExportForm = () => {
    handleExportJson({ id: formId, name: formName });
    handleClose();
  };

  // -- Deletion --
  const [commitDelete] = useApiMutation(formPopoverDeletionMutation);
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;

  const submitDelete = () => {
    setDeleting(true);
    commitDelete({
      variables: {
        id: formId,
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_forms', paginationOptions, formId);

        // Manual update of the globalCount in pageInfo
        const root = store.getRoot();
        const paginationParams = { ...paginationOptions };
        delete paginationParams.count;
        const conn = ConnectionHandler.getConnection(
          root,
          'Pagination_forms',
          paginationParams,
        );
        if (conn) {
          const pageInfo = conn.getLinkedRecord('pageInfo');
          if (pageInfo) {
            const currentCount = pageInfo.getValue('globalCount');
            if (typeof currentCount === 'number' && currentCount > 0) {
              pageInfo.setValue(currentCount - 1, 'globalCount');
            }
          }
        }
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        <MenuItem onClick={handleOpenUpdate}>
          {t_i18n('Update')}
        </MenuItem>
        <MenuItem onClick={handleOpenDuplicate}>
          {t_i18n('Duplicate')}
        </MenuItem>
        <MenuItem onClick={handleExportForm}>
          {t_i18n('Export')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <>
            <FormEditionContainer
              queryRef={queryRef}
              handleClose={() => setDisplayUpdate(false)}
              open={displayUpdate}
            />
            <FormCreationContainer
              queryRef={queryRef}
              handleClose={() => setDisplayDuplicate(false)}
              open={displayDuplicate}
              onOpen={() => {}} // Not needed for inline duplication
              triggerButton={false}
              paginationOptions={paginationOptions}
              drawerSettings={{
                title: t_i18n('Duplicate a form'),
                button: t_i18n('Duplicate'),
              }}
            />
          </>
        </React.Suspense>
      )}
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this form?')}
      />
    </div>
  );
};

export default FormPopover;
