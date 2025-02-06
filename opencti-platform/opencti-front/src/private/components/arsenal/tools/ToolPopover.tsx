import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import useDeletion from '../../../../utils/hooks/useDeletion';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import ToolEditionContainer, { toolEditionQuery } from './ToolEditionContainer';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { ToolEditionContainerQuery } from './__generated__/ToolEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useHelper from '../../../../utils/hooks/useHelper';
import DeleteDialog from '../../../../components/DeleteDialog';

const toolPopoverDeletionMutation = graphql`
  mutation ToolPopoverDeletionMutation($id: ID!) {
    toolEdit(id: $id) {
      delete
    }
  }
`;

type ToolPopoverProps = {
  id: string;
};

const ToolPopover: React.FC<ToolPopoverProps> = ({ id }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();

  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [displayEnrichment, setDisplayEnrichment] = useState<boolean>(false);

  const [commit] = useApiMutation(toolPopoverDeletionMutation);
  const queryRef = useQueryLoading<ToolEditionContainerQuery>(toolEditionQuery, { id });

  const deletion = useDeletion({ handleClose: () => setAnchorEl(null) });

  const handleOpen = (event: React.MouseEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(undefined);
  };

  const handleCloseEdit = () => {
    setDisplayEdit(false);
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };

  const handleOpenEnrichment = () => {
    setDisplayEnrichment(true);
    handleClose();
  };

  const handleCloseEnrichment = () => {
    setDisplayEnrichment(false);
  };

  const submitDelete = () => {
    deletion.setDeleting(true);
    commit({
      variables: { id },
      onCompleted: () => {
        deletion.setDeleting(false);
        navigate('/dashboard/arsenal/tools');
      },
    });
  };

  return isFABReplaced
    ? (<></>)
    : (
      <div>
        <ToggleButton value="popover" size="small" onClick={handleOpen}>
          <MoreVert fontSize="small" color="primary" />
        </ToggleButton>
        <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
          <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
            <MenuItem onClick={handleOpenEnrichment}>{t_i18n('Enrich')}</MenuItem>
          </Security>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem onClick={deletion.handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        </Menu>
        <StixCoreObjectEnrichment
          stixCoreObjectId={id}
          open={displayEnrichment}
          handleClose={handleCloseEnrichment}
        />
        <DeleteDialog
          deletion={deletion}
          submitDelete={submitDelete}
          message={t_i18n('Do you want to delete this tool?')}
        />
        {queryRef && (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <ToolEditionContainer
              queryRef={queryRef}
              open={displayEdit}
              handleClose={handleCloseEdit}
            />
          </React.Suspense>
        )}
      </div>
    );
};

export default ToolPopover;
