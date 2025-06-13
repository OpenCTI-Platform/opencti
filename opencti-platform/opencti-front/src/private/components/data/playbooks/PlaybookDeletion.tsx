/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import Button from '@mui/material/Button';
import { handleError } from '../../../../relay/environment';
import DeleteDialog from '../../../../components/DeleteDialog';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const playbookDeletionMutation = graphql`
  mutation PlaybookDeletionMutation($id: ID!) {
    playbookDelete(id: $id)
  }
`;

const PlaybookDeletion = ({ id }: { id: string }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();

  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Playbook') },
  });
  const [commit] = useApiMutation(
    playbookDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const handleClose = () => {};
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, deleting } = deletion;

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/data/processing/automation');
      },
      onError: (error: Error) => {
        handleError(error);
        handleClose();
      },
    });
  };
  return (
    <>
      <Button
          color="error"
          variant="contained"
          onClick={handleOpenDelete}
          disabled={deleting}
          sx={{ marginTop: 2 }}
           >
          {t_i18n('Delete')}
        </Button>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this playbook?')}
      />
    </>
  );
};

export default PlaybookDeletion;
