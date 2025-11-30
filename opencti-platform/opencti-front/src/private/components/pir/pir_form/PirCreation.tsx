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

import React, { useState } from 'react';
import { Dialog } from '@mui/material';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { PirsListQuery$variables } from '../__generated__/PirsListQuery.graphql';
import { PirCreationFormData, pirFormDataToMutationInput } from './pir-form-utils';
import { PirCreationMutation } from './__generated__/PirCreationMutation.graphql';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import Transition from '../../../../components/Transition';
import PirCreationForm from './PirCreationForm';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';

const pirCreateMutation = graphql`
  mutation PirCreationMutation($input: PirAddInput!) {
    pirAdd(input: $input) {
      ...Pirs_PirFragment
    }
  }
`;

interface PirCreationProps {
  paginationOptions: PirsListQuery$variables
}

const PirCreation = ({ paginationOptions }: PirCreationProps) => {
  const { t_i18n } = useFormatter();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [createMutation] = useApiMutation<PirCreationMutation>(
    pirCreateMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Pir')} ${t_i18n('successfully created')}` },
  );

  const handleOpenDialog = () => setDialogOpen(true);
  const handleCloseDialog = () => setDialogOpen(false);

  const submit = (data: PirCreationFormData) => {
    const input = pirFormDataToMutationInput(data);
    createMutation({
      variables: { input },
      onCompleted: () => {
        setDialogOpen(false);
      },
      onError: () => {
        setDialogOpen(false);
      },
      updater: (store: RecordSourceSelectorProxy) => insertNode(
        store,
        'Pagination_pirs',
        paginationOptions,
        'pirAdd',
      ),
    });
  };

  return (
    <>
      <CreateEntityControlledDial
        entityType='Pir'
        onOpen={handleOpenDialog}
      />

      <Dialog
        fullWidth
        open={dialogOpen}
        slots={{ transition: Transition }}
        slotProps={{
          paper: {
            elevation: 1,
            style: { minWidth: '950px' },
          },
        }}
        onClose={handleCloseDialog}
      >
        <PirCreationForm
          onCancel={handleCloseDialog}
          onSubmit={submit}
        />
      </Dialog>
    </>
  );
};

export default PirCreation;
