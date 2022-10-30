import React, { useState, Suspense } from 'react';
import { useHistory } from 'react-router-dom';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useLazyLoadQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { reportEditionQuery } from './ReportEdition';
import ReportEditionContainer from './ReportEditionContainer';
import Loader from '../../../../components/Loader';
import Security, {
  KNOWLEDGE_KNUPDATE_KNDELETE,
} from '../../../../utils/Security';
import Transition from '../../../../components/Transition';

const useStyles = makeStyles((theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
}));

const ReportPopoverDeletionMutation = graphql`
  mutation ReportPopoverDeletionMutation($id: ID!, $purgeElements: Boolean) {
    reportEdit(id: $id) {
      delete(purgeElements: $purgeElements)
    }
  }
`;

const ReportPopover = (props) => {
  const { id } = props;
  const history = useHistory();
  const classes = useStyles();
  const { t } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [purgeElements, setPurgeElements] = useState(false);
  const handleOpen = (event) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => {
    setPurgeElements(false);
    setDisplayDelete(false);
  };
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: ReportPopoverDeletionMutation,
      variables: { id, purgeElements },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        history.push('/dashboard/analysis/reports');
      },
    });
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);
  const data = useLazyLoadQuery(reportEditionQuery, { id });
  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        size="large"
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenEdit}>{t('Update')}</MenuItem>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <MenuItem onClick={handleOpenDelete}>{t('Delete')}</MenuItem>
        </Security>
      </Menu>
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <Typography variant="body">
            {t('Do you want to delete this report?')}
          </Typography>
          <Alert
            severity="warning"
            variant="outlined"
            style={{ marginTop: 10 }}
          >
            <AlertTitle>{t('Cascade delete')}</AlertTitle>
            <FormGroup>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={purgeElements}
                    onChange={() => setPurgeElements(!purgeElements)}
                  />
                }
                label={t('Delete elements which are only in this report')}
              />
            </FormGroup>
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      <Drawer
        open={displayEdit}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleCloseEdit}
      >
        <Suspense fallback={<Loader variant="inElement" />}>
          <ReportEditionContainer
            report={data.report}
            handleClose={handleCloseEdit}
          />
        </Suspense>
      </Drawer>
    </div>
  );
};

export default ReportPopover;
