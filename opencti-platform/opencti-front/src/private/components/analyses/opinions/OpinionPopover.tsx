import React, { FunctionComponent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import ToggleButton from '@mui/material/ToggleButton';
import IconButton from '@common/button/IconButton';
import { Formik } from 'formik';
import { PopoverProps } from '@mui/material/Popover';
import { OpinionEditionContainerQuery$data } from '@components/analyses/opinions/__generated__/OpinionEditionContainerQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { opinionEditionQuery } from './OpinionEdition';
import { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import OpinionEditionContainer from './OpinionEditionContainer';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';

const OpinionPopoverDeletionMutation = graphql`
  mutation OpinionPopoverDeletionMutation($id: ID!) {
    opinionEdit(id: $id) {
      delete
    }
  }
`;

interface CreatedBy {
  id: string;
  name: string;
}

interface ObjectMarking {
  readonly definition: string | null | undefined;
  readonly definition_type: string | null | undefined;
}

interface OpinionPopoverProps {
  variant: string;
  onDelete: () => void;
  opinion: {
    id: string;
    opinion: string;
    explanation: string | null | undefined;
    createdBy: CreatedBy | null | undefined;
    objectMarking: readonly ObjectMarking[] | null | undefined; // Mark as readonly
  };
}

const OpinionPopover: FunctionComponent<OpinionPopoverProps> = ({ opinion, variant = 'overview', onDelete }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const handleOpen = (event: React.SyntheticEvent) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => setDisplayDelete(false);
  const [commit] = useApiMutation(OpinionPopoverDeletionMutation);
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: { id: opinion.id },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
        if (onDelete) {
          onDelete();
        }
        if (variant !== 'inList') {
          navigate('/dashboard/analyses/opinions');
        }
      },
      updater: (store) => {
        store.delete(opinion.id);
      },
    });
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);
  return (
    <>
      {variant === 'inList' ? (
        <IconButton
          onClick={handleOpen}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
          color="primary"
        >
          <MoreVert />
        </IconButton>
      ) : (
        <ToggleButton
          value="popover"
          size="small"
          onClick={handleOpen}
        >
          <MoreVert fontSize="small" color="primary" />
        </ToggleButton>
      )}
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        {variant !== 'inList' && <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>}
        <CollaborativeSecurity
          data={opinion}
          needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}
        >
          <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        </CollaborativeSecurity>
      </Menu>
      <Formik
        initialValues={{}}
        onSubmit={submitDelete}
        onReset={handleCloseDelete}
      >
        {({ submitForm, handleReset }) => (
          <Dialog
            open={displayDelete}
            slotProps={{ paper: { elevation: 1 } }}
            slots={{ transition: Transition }}
            onClose={handleCloseDelete}
          >
            <DialogContent>
              <DialogContentText>
                {t_i18n('Do you want to delete this opinion?')}
              </DialogContentText>
            </DialogContent>
            <DialogActions>
              <Button variant="secondary" onClick={handleReset} disabled={deleting}>
                {t_i18n('Cancel')}
              </Button>
              <Button onClick={submitForm} disabled={deleting}>
                {t_i18n('Delete')}
              </Button>
            </DialogActions>
          </Dialog>
        )}

      </Formik>
      {variant !== 'inList' && (
        <QueryRenderer
          query={opinionEditionQuery}
          variables={{ id: opinion.id }}
          render={({ props }: { props: OpinionEditionContainerQuery$data }) => {
            if (props) {
              return (
                <OpinionEditionContainer
                  opinion={props.opinion}
                  handleClose={handleCloseEdit}
                  open={displayEdit}
                />
              );
            }
            return <div />;
          }}
        />
      )}
    </>
  );
};

export default OpinionPopover;
