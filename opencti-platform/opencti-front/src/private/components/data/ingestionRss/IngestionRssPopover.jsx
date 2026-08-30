import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import MoreVert from '@mui/icons-material/MoreVert';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Slide from '@mui/material/Slide';
import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer, fetchQuery } from '../../../../relay/environment';
import { deleteNode } from '../../../../utils/store';
import IngestionRssEdition, { ingestionRssMutationFieldPatch } from './IngestionRssEdition';
import fileDownload from 'js-file-download';
import stopEvent from '../../../../utils/domEvent';

const styles = (theme) => ({
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
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const ingestionRssPopoverDeletionMutation = graphql`
  mutation IngestionRssPopoverDeletionMutation($id: ID!) {
    ingestionRssDelete(id: $id)
  }
`;

const ingestionRssPopoverExportQuery = graphql`
  query IngestionRssPopoverExportQuery($id: String!) {
    ingestionRss(id: $id) {
      name
      toConfigurationExport
    }
  }
`;

const ingestionRssEditionQuery = graphql`
  query IngestionRssPopoverEditionQuery($id: String!) {
    ingestionRss(id: $id) {
      id
      name
      uri
      ingestion_running
      current_state_date
      ...IngestionRssEdition_ingestionRss
    }
  }
`;

const IngestionRssPopover = (props) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [displayStart, setDisplayStart] = useState(false);
  const [starting, setStarting] = useState(false);
  const [displayStop, setDisplayStop] = useState(false);
  const [stopping, setStopping] = useState(false);
  const handleOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };

  const handleCloseUpdate = () => {
    setDisplayUpdate(false);
  };

  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

  const handleOpenStart = () => {
    setDisplayStart(true);
    handleClose();
  };

  const handleCloseStart = () => {
    setDisplayStart(false);
  };

  const handleOpenStop = () => {
    setDisplayStop(true);
    handleClose();
  };

  const handleCloseStop = () => {
    setDisplayStop(false);
  };

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: ingestionRssPopoverDeletionMutation,
      variables: {
        id: props.ingestionRssId,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_ingestionRsss',
          props.paginationOptions,
          props.ingestionRssId,
        );
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
        if (props.onDeleteComplete) {
          props.onDeleteComplete();
        }
      },
    });
  };

  const exportRssFeed = async () => {
    const { ingestionRss } = await fetchQuery(
      ingestionRssPopoverExportQuery,
      { id: props.ingestionRssId },
    ).toPromise();

    if (ingestionRss) {
      const blob = new Blob([ingestionRss.toConfigurationExport], { type: 'text/json' });
      const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
      const fileName = `${year}${month}${day}_rssFeed_${ingestionRss.name}.json`;
      fileDownload(blob, fileName);
    }
  };

  const handleExport = async (e) => {
    stopEvent(e);
    handleClose();
    await exportRssFeed();
  };

  const submitStart = () => {
    setStarting(true);
    commitMutation({
      mutation: ingestionRssMutationFieldPatch,
      variables: {
        id: props.ingestionRssId,
        input: { key: 'ingestion_running', value: ['true'] },
      },
      onCompleted: () => {
        setStarting(false);
        handleCloseStart();
      },
    });
  };

  const submitStop = () => {
    setStopping(true);
    commitMutation({
      mutation: ingestionRssMutationFieldPatch,
      variables: {
        id: props.ingestionRssId,
        input: { key: 'ingestion_running', value: ['false'] },
      },
      onCompleted: () => {
        setStopping(false);
        handleCloseStop();
      },
    });
  };

  const { classes, ingestionRssId, running } = props;
  return (
    <div className={classes.container}>
      <IconButton
        aria-label={t_i18n('Open menu')}
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        {!running && (
          <MenuItem onClick={handleOpenStart}>
            {t_i18n('Start')}
          </MenuItem>
        )}
        {running && (
          <MenuItem onClick={handleOpenStop}>
            {t_i18n('Stop')}
          </MenuItem>
        )}
        <MenuItem onClick={handleOpenUpdate}>
          {t_i18n('Update')}
        </MenuItem>
        <MenuItem onClick={handleExport}>
          {t_i18n('Export')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
      <QueryRenderer
        query={ingestionRssEditionQuery}
        variables={{ id: ingestionRssId }}
        render={({ props }) => {
          if (props) {
            return (
              <IngestionRssEdition
                ingestionRss={props.ingestionRss}
                handleClose={handleCloseUpdate}
                open={displayUpdate}
              />
            );
          }
          return <div />;
        }}
      />
      <Dialog
        open={displayDelete}
        onClose={handleCloseDelete}
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('Do you want to delete this RSS ingester?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseDelete}
            disabled={deleting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitDelete}
            disabled={deleting}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayStart}
        slots={{ transition: Transition }}
        onClose={handleCloseStart}
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('Do you want to start this RSS ingester?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseStart}
            disabled={starting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitStart}
            disabled={starting}
          >
            {t_i18n('Start')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayStop}
        onClose={handleCloseStop}
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('Do you want to stop this RSS ingester?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseStop}
            disabled={stopping}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitStop}
            disabled={stopping}
          >
            {t_i18n('Stop')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

IngestionRssPopover.propTypes = {
  ingestionRssId: PropTypes.string,
  running: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  onDeleteComplete: PropTypes.func,
};

export default compose(withStyles(styles))(IngestionRssPopover);
