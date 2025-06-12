import { MenuItem } from '@mui/material';
import React, { FunctionComponent } from 'react';
import { Disposable, graphql, RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { deleteNode } from '../../../../utils/store';
import { ThemesLinesSearchQuery$variables } from './__generated__/ThemesLinesSearchQuery.graphql';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useDeletion from '../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../components/DeleteDialog';

const deleteThemeMutation = graphql`
  mutation ThemeDeletionMutation($id: ID!) {
    themeDelete(id:$id)
  }
`;

interface ThemeDeletionProps {
  id: string;
  disabled: boolean;
  handleRefetch: () => Disposable;
  paginationOptions: ThemesLinesSearchQuery$variables;
}

const ThemeDeletion: FunctionComponent<ThemeDeletionProps> = ({
  id,
  disabled,
  handleRefetch,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('Theme') },
  });
  const [commit] = useApiMutation(
    deleteThemeMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const handleClose = () => {};
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, deleting } = deletion;

  const submitDelete = () => {
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
    <>
      <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
        <MenuItem
          onClick={handleOpenDelete}
          aria-label={t_i18n('Delete')}
          disabled={disabled || deleting}
        >
          {t_i18n('Delete')}
        </MenuItem>
      </Security>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this theme?')}
      />
    </>
  );
};

export default ThemeDeletion;
