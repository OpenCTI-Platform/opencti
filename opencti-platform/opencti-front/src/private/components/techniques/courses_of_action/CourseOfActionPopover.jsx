import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { courseOfActionEditionQuery } from './CourseOfActionEdition';
import CourseOfActionEditionContainer from './CourseOfActionEditionContainer';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const CourseOfActionPopoverDeletionMutation = graphql`
  mutation CourseOfActionPopoverDeletionMutation($id: ID!) {
    courseOfActionEdit(id: $id) {
      delete
    }
  }
`;

const CourseOfActionPopover = ({ id }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayEdit, setDisplayEdit] = useState(false);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const handleOpen = (event) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: CourseOfActionPopoverDeletionMutation,
      variables: { id },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/techniques/courses_of_action');
      },
    });
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);
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
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        </Menu>
        <DeleteDialog
          deletion={deletion}
          submitDelete={submitDelete}
          message={t_i18n('Do you want to delete this course of action?')}
        />
        <QueryRenderer
          query={courseOfActionEditionQuery}
          variables={{ id }}
          render={({ props }) => {
            if (props) {
              return (
                <CourseOfActionEditionContainer
                  courseOfAction={props.courseOfAction}
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

export default CourseOfActionPopover;
