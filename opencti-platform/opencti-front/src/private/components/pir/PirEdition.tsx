import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { PirEditionMutation } from './__generated__/PirEditionMutation.graphql';
import { PirEditionFragment$key } from './__generated__/PirEditionFragment.graphql';
import { useFormatter } from '../../../components/i18n';
import PirEditionForm, { PirEditionFormInputKeys } from './PirEditionForm';
import useApiMutation from '../../../utils/hooks/useApiMutation';

const pirEditMutation = graphql`
  mutation PirEditionMutation($id: ID!, $input: [EditInput!]!) {
    pirFieldPatch(id: $id, input: $input) {
      ...PirEditionFragment
    }
  }
`;

const editionFragment = graphql`
  fragment PirEditionFragment on Pir {
    id
    name
    description
  }
`;

interface PirEditionProps {
  isOpen: boolean
  onClose: () => void
  data: PirEditionFragment$key
}

const PirEdition = ({
  data,
  isOpen,
  onClose,
}: PirEditionProps) => {
  const { t_i18n } = useFormatter();
  const pir = useFragment(editionFragment, data);

  const [editMutation] = useApiMutation<PirEditionMutation>(
    pirEditMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Pir')} ${t_i18n('successfully updated')}` },
  );

  const onEdit = (field: PirEditionFormInputKeys, value: unknown) => {
    const input: { key:string, value: [unknown] } = { key: field, value: [value] };
    editMutation({
      variables: { id: pir.id, input: [input] },
    });
  };

  return (
    <Drawer
      title={t_i18n('Update a PIR')}
      open={isOpen}
      onClose={onClose}
    >
      <PirEditionForm onSubmitField={onEdit} pir={pir} />
    </Drawer>
  );
};

export default PirEdition;
