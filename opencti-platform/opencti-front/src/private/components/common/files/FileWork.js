import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { propOr, compose } from 'ramda';
import { v4 as uuid } from 'uuid';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import {
  CheckCircleOutlined,
  DeleteOutlined,
  WarningOutlined,
} from '@mui/icons-material';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import * as R from 'ramda';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  nested: {
    paddingLeft: theme.spacing(4),
  },
  nestedNested: {
    paddingLeft: theme.spacing(8),
  },
  tooltip: {
    maxWidth: 600,
  },
});

const fileWorkDeleteMutation = graphql`
  mutation FileWorkDeleteMutation($workId: ID!) {
    workEdit(id: $workId) {
      delete
    }
  }
`;

const FileWorkComponent = (props) => {
  const {
    t,
    nsdt,
    classes,
    file: { works },
    nested,
  } = props;
  const [deleting, setDeleting] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(null);
  const deleteWork = (workId) => {
    commitMutation({
      mutation: fileWorkDeleteMutation,
      variables: { workId },
      optimisticUpdater: (store) => {
        const fileStore = store.get(workId);
        fileStore.setValue('deleting', 'status');
      },
      updater: (store) => {
        const fileStore = store.get(workId);
        fileStore.setValue('deleting', 'status');
      },
      onCompleted: () => {
        setDeleting(false);
        setDisplayDelete(null);
      },
    });
  };
  return (
    <List component="div" disablePadding={true}>
      {works
        && works.map((work) => {
          const messages = R.sortBy(R.prop('timestamp'), [
            ...work.messages,
            ...work.errors,
          ]);
          const messageToDisplay = (
            <div>
              {messages.length > 0
                ? R.map(
                  (message) => (
                      <div key={message.message}>
                        [{nsdt(message.timestamp)}] {message.message}
                      </div>
                  ),
                  messages,
                )
                : t(work.status)}
            </div>
          );
          const numberOfError = work.errors.length;
          const secondaryLabel = `${nsdt(work.timestamp)} `;
          const { tracking } = work;
          const computeLabel = () => {
            let statusText = '';
            if (!work.received_time) {
              statusText = ' (Pending)';
            } else if (tracking.import_expected_number > 0) {
              statusText = ` (${tracking.import_processed_number}/${tracking.import_expected_number})`;
            }
            if (numberOfError > 0) {
              statusText += ` - [ ${numberOfError} error${
                numberOfError > 1 ? 's' : ''
              } ]`;
            }
            return `${propOr(
              t('Deleted'),
              'name',
              work.connector,
            )}${statusText}`;
          };
          return (
            <Tooltip
              title={messageToDisplay}
              key={uuid()}
              classes={{ tooltip: classes.tooltip }}
            >
              <ListItem
                dense={true}
                button={true}
                divider={true}
                classes={{ root: nested ? classes.nestedNested : classes.nested }}
                disabled={work.status === 'deleting'}
              >
                <ListItemIcon>
                  {work.status === 'complete' && numberOfError === 0 && (
                    <CheckCircleOutlined
                      style={{ fontSize: 15, color: '#4caf50' }}
                    />
                  )}
                  {work.status === 'complete' && numberOfError > 0 && (
                    <WarningOutlined
                      style={{ fontSize: 15, color: '#f44336' }}
                    />
                  )}
                  {(work.status === 'progress'
                    || work.status === 'wait'
                    || work.status === 'deleting') && (
                    <CircularProgress
                      size={20}
                      thickness={2}
                      style={{ marginRight: 10 }}
                    />
                  )}
                </ListItemIcon>
                <ListItemText
                  primary={computeLabel()}
                  secondary={secondaryLabel}
                />
                <ListItemSecondaryAction>
                  <Tooltip title={t('Delete')}>
                    <span>
                      <IconButton
                        color="primary"
                        onClick={() => setDisplayDelete(work.id)}
                        disabled={work.status === 'deleting'}
                        size="large"
                      >
                        <DeleteOutlined />
                      </IconButton>
                    </span>
                  </Tooltip>
                </ListItemSecondaryAction>
              </ListItem>
            </Tooltip>
          );
        })}
      <Dialog
        open={displayDelete !== null}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={() => setDisplayDelete(null)}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to remove this job?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDisplayDelete(null)} disabled={deleting}>
            {t('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={() => deleteWork(displayDelete)}
            disabled={deleting}
          >
            {t('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </List>
  );
};

FileWorkComponent.propTypes = {
  classes: PropTypes.object,
  file: PropTypes.object.isRequired,
  nsdt: PropTypes.func,
  nested: PropTypes.bool,
};

const FileWork = createFragmentContainer(FileWorkComponent, {
  file: graphql`
    fragment FileWork_file on File {
      id
      works {
        id
        connector {
          name
        }
        user {
          name
        }
        received_time
        tracking {
          import_expected_number
          import_processed_number
        }
        messages {
          timestamp
          message
        }
        errors {
          timestamp
          message
        }
        status
        timestamp
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(FileWork);
