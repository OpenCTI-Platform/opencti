import React, { useState } from 'react';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { graphql } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import { DecayExclusionRules_node$data } from '@components/settings/decay/__generated__/DecayExclusionRules_node.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { deleteNode } from '../../../../utils/store';
import useDeletion from '../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../components/DeleteDialog';
import { DecayExclusionRulesLinesPaginationQuery$variables } from './__generated__/DecayExclusionRulesLinesPaginationQuery.graphql';
import DecayExclusionRuleEdition, { decayExclusionRuleEditionFieldPatch } from './DecayExclusionRuleEdition';

const decayExclusionRulePopoverDeleteMutation = graphql`
  mutation DecayExclusionRulePopoverDeleteMutation($id: ID!) {
    decayExclusionRuleDelete(id: $id)
  }
`;

type DecayExclusionRulePopoverProps = {
  data: DecayExclusionRules_node$data;
  paginationOptions: DecayExclusionRulesLinesPaginationQuery$variables;
};

const DecayExclusionRulePopover = ({ data, paginationOptions }: DecayExclusionRulePopoverProps) => {
  const { t_i18n } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [isEditionFormOpen, setIsEditionFormOpen] = useState<boolean>(false);

  const [commit] = useApiMutation(decayExclusionRulePopoverDeleteMutation);
  const [commitFieldPatch] = useApiMutation(decayExclusionRuleEditionFieldPatch);

  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClosePopover = () => setAnchorEl(null);

  const handleOpenEditionForm = () => {
    setIsEditionFormOpen(true);
    handleClosePopover();
  };
  const handleCloseEditionForm = () => setIsEditionFormOpen(false);

  const handleEnable = () => {
    commitFieldPatch({
      variables: {
        id: data.id,
        input: [{ key: 'active', value: !data.active }],
      },
    });
    handleClosePopover();
  };

  const deletion = useDeletion({ handleClose: handleClosePopover });
  const { setDeleting, handleCloseDelete, handleOpenDelete } = deletion;

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: { id: data.id },
      updater: (store) => {
        deleteNode(store, 'Pagination_decayExclusionRules', paginationOptions, data.id);
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  return (
    <>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClosePopover}>
        <MenuItem onClick={handleEnable}>{data.active ? t_i18n('Disable') : t_i18n('Enable')}</MenuItem>
        <MenuItem onClick={handleOpenEditionForm}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this decay exclusion rule?')}
      />
      <DecayExclusionRuleEdition
        data={data}
        isOpen={isEditionFormOpen}
        onClose={handleCloseEditionForm}
      />
    </>
  );
};

export default DecayExclusionRulePopover;
