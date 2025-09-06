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

import { graphql } from 'react-relay';
import React, { ReactNode, UIEvent } from 'react';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { PirDeletionMutation } from './__generated__/PirDeletionMutation.graphql';
import useDeletion from '../../../utils/hooks/useDeletion';
import stopEvent from '../../../utils/domEvent';
import DeleteDialog from '../../../components/DeleteDialog';

const pirDeleteMutation = graphql`
  mutation PirDeletionMutation($id: ID!) {
    pirDelete(id: $id)
  }
`;

interface ChildrenProps {
  handleOpenDelete: (e?: UIEvent) => void
  deleting: boolean
}

interface PirDeletionProps {
  pirId: string
  onDeleteComplete?: () => void
  children: (props: ChildrenProps) => ReactNode
}

const PirDeletion = ({ pirId, onDeleteComplete, children }: PirDeletionProps) => {
  const { t_i18n } = useFormatter();

  const [deleteMutation, deleting] = useApiMutation<PirDeletionMutation>(
    pirDeleteMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Pir')} ${t_i18n('successfully deleted')}` },
  );

  const deletion = useDeletion({});
  const { handleOpenDelete, handleCloseDelete } = deletion;

  const onDelete = (e: UIEvent) => {
    stopEvent(e);
    deleteMutation({
      variables: { id: pirId },
      onCompleted: () => {
        handleCloseDelete();
        onDeleteComplete?.();
      },
      onError: () => {
        handleCloseDelete();
      },
    });
  };

  return (
    <>
      {children({ handleOpenDelete, deleting })}
      <DeleteDialog
        deletion={deletion}
        submitDelete={onDelete}
        message={t_i18n('Do you want to delete this PIR?')}
      />
    </>
  );
};

export default PirDeletion;
