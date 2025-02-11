import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import { channelEditionQuery } from './ChannelEdition';
import ChannelEditionContainer from './ChannelEditionContainer';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const ChannelPopoverDeletionMutation = graphql`
  mutation ChannelPopoverDeletionMutation($id: ID!) {
    channelDelete(id: $id)
  }
`;

const ChannelPopover = ({ id }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [displayEnrichment, setDisplayEnrichment] = useState(false);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const handleOpen = (event) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const deletion = useDeletion({});
  const submitDelete = () => {
    deletion.setDeleting(true);
    commitMutation({
      mutation: ChannelPopoverDeletionMutation,
      variables: { id },
      onCompleted: () => {
        deletion.setDeleting(false);
        handleClose();
        navigate('/dashboard/arsenal/channels');
      },
    });
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);
  const handleOpenEnrichment = () => {
    setDisplayEnrichment(true);
    handleClose();
  };
  const handleCloseEnrichment = () => {
    setDisplayEnrichment(false);
  };
  return isFABReplaced
    ? (<></>)
    : (
      <>
        <ToggleButton
          value="popover"
          size="small"
          onClick={handleOpen}
        >
          <MoreVert fontSize="small" color="primary" />
        </ToggleButton>
        <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
          </Security>
          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
            <MenuItem onClick={handleOpenEnrichment}>{t_i18n('Enrich')}</MenuItem>
          </Security>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem onClick={deletion.handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        </Menu>
        <StixCoreObjectEnrichment stixCoreObjectId={id} open={displayEnrichment} handleClose={handleCloseEnrichment} />
        <DeleteDialog
          deletion={deletion}
          submitDelete={submitDelete}
          message={t_i18n('Do you want to delete this channel?')}
        />
        <QueryRenderer
          query={channelEditionQuery}
          variables={{ id }}
          render={({ props }) => {
            if (props) {
              return (
                <ChannelEditionContainer
                  channel={props.channel}
                  handleClose={handleCloseEdit}
                  open={displayEdit}
                />
              );
            }
            return <div />;
          }}
        />
      </>
    );
};

export default ChannelPopover;
