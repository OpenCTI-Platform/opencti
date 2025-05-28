import React, { useState } from 'react';
import { Dialog } from '@mui/material';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { PirsListQuery$variables } from './__generated__/PirsListQuery.graphql';
import { PirCreationFormData, pirFormDataToMutationInput } from './pir-form-utils';
import { PirCreationMutation } from './__generated__/PirCreationMutation.graphql';
import CreateEntityControlledDial from '../../../components/CreateEntityControlledDial';
import Transition from '../../../components/Transition';
import PirCreationForm from './PirCreationForm';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../components/i18n';
import { insertNode } from '../../../utils/store';

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
        onOpen={() => setDialogOpen(true)}
      />

      <Dialog
        fullWidth
        open={dialogOpen}
        slots={{ transition: Transition }}
        slotProps={{
          paper: {
            elevation: 1,
            style: { minWidth: '900px' },
          },
        }}
      >
        <PirCreationForm
          onCancel={() => setDialogOpen(false)}
          onSubmit={submit}
        />
      </Dialog>
    </>
  );
};

export default PirCreation;
