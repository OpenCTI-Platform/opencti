import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import StixCoreObjectEnrollPlaybook from '../../common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { indicatorEditionQuery } from './IndicatorEdition';
import IndicatorEditionContainer from './IndicatorEditionContainer';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const IndicatorPopoverDeletionMutation = graphql`
  mutation IndicatorPopoverDeletionMutation($id: ID!) {
    indicatorDelete(id: $id)
  }
`;

const IndicatorPopover = ({ id }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayEnroll, setDisplayEnroll] = useState(false);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [displayEnrichment, setDisplayEnrichment] = useState(false);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const handleOpen = (event) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: IndicatorPopoverDeletionMutation,
      variables: { id },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/observations/indicators');
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
  const handleOpenEnroll = () => {
    setDisplayEnroll(true);
    handleClose();
  };
  const handleCloseEnroll = () => {
    setDisplayEnroll(false);
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
          <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
            <MenuItem onClick={handleOpenEnrichment}>{t_i18n('Enrich')}</MenuItem>
          </Security>
          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
            <MenuItem onClick={handleOpenEnroll}>
              {t_i18n('Enroll in playbook')}
            </MenuItem>
          </Security>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        </Menu>
        <StixCoreObjectEnrichment stixCoreObjectId={id} open={displayEnrichment} handleClose={handleCloseEnrichment} />
        <StixCoreObjectEnrollPlaybook stixCoreObjectId={id} open={displayEnroll} handleClose={handleCloseEnroll} />
        <DeleteDialog
          deletion={deletion}
          submitDelete={submitDelete}
          message={t_i18n('Do you want to delete this indicator?')}
        />
        <QueryRenderer
          query={indicatorEditionQuery}
          variables={{ id }}
          render={({ props }) => {
            if (props) {
              return (
                <IndicatorEditionContainer
                  indicator={props.indicator}
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

export default IndicatorPopover;
