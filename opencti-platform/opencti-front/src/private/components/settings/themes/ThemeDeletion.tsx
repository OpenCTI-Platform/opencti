import { Button, Dialog, DialogActions, DialogContent, DialogContentText } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import { Disposable, graphql, RecordSourceSelectorProxy } from 'relay-runtime';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { deleteNode } from '../../../../utils/store';
import { ThemesLinesSearchQuery$variables } from './__generated__/ThemesLinesSearchQuery.graphql';

const deleteThemeMutation = graphql`
  mutation ThemeDeletionMutation($id: ID!) {
    themeDelete(id:$id)
  }
`;

interface ThemeDeletionProps {
  id: string;
  open: boolean;
  handleClose: () => void;
  handleRefetch: () => Disposable;
  paginationOptions: ThemesLinesSearchQuery$variables;
}

const ThemeDeletion: FunctionComponent<ThemeDeletionProps> = ({
  id,
  open,
  handleClose,
  handleRefetch,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [deleting, setDeleting] = useState<boolean>(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('Theme') },
  });
  const [commit] = useApiMutation(
    deleteThemeMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const handleDelete = () => {
    setDeleting(true);
    commit({
      variables: { id },
      updater: (store: RecordSourceSelectorProxy) => deleteNode(
        store,
        'Pagination_themes',
        paginationOptions,
        id,
      ),
      onCompleted: () => {
        setDeleting(false);
        handleRefetch();
      },
    });
    handleClose();
  };

  return (
    <Dialog
      PaperProps={{ elevation: 1 }}
      open={open}
      keepMounted
      TransitionComponent={Transition}
      onClose={handleClose}
    >
      <DialogContent>
        <DialogContentText>
          {t_i18n('Do you want to delete this theme?')}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={deleting}>
          {t_i18n('Cancel')}
        </Button>
        <Button color="secondary" onClick={handleDelete} disabled={deleting}>
          {t_i18n('Delete')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ThemeDeletion;
