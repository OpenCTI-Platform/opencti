import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose, propOr } from 'ramda';
import { v4 as uuid } from 'uuid';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ArchitectureOutlined, CheckCircleOutlined, DeleteOutlined, WarningOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import Slide from '@mui/material/Slide';
import { useNavigate } from 'react-router-dom';
import { commitMutation } from '../../../../relay/environment';
import inject18n, { useFormatter } from '../../../../components/i18n';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

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
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    marginRight: 10,
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
  const { t_i18n } = useFormatter();
  const [workId, setWorkId] = useState(null);
  const navigate = useNavigate();
  const draftContext = useDraftContext();
  const deletion = useDeletion({});
  const { handleOpenDelete, handleCloseDelete, setDeleting } = deletion;

  const navigateToDraft = (draftId) => navigate(`/dashboard/data/import/draft/${draftId}`);

  const handleDelete = (id) => {
    setWorkId(id);
    handleOpenDelete();
  };

  const deleteWork = () => {
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
        setWorkId(null);
        handleCloseDelete();
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
            <>
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
            </>
          );
          const numberOfError = work.errors.length;
          const secondaryLabel = `${nsdt(work.timestamp)} `;
          const { tracking } = work;
          const computeLabel = () => {
            let statusText = '';
            if (!work.received_time) {
              statusText = ' (Pending)';
            } else if (tracking.import_expected_number > 0) {
              statusText = ` (${tracking.import_processed_number || 0}/${tracking.import_expected_number})`;
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
          const isCurrentContextWork = (!draftContext || work.draft_context === draftContext.id);
          return (
            <Tooltip
              title={messageToDisplay}
              key={uuid()}
              classes={{ tooltip: classes.tooltip }}
            >
              <ListItem
                dense={true}
                divider={true}
                classes={{
                  root: nested ? classes.nestedNested : classes.nested,
                }}
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
                  primary={
                    <span className={classes.itemText}>{computeLabel()}</span>
                  }
                  secondary={
                    <span className={classes.itemText}>{secondaryLabel}</span>
                  }
                />
                {!!work.draft_context && !draftContext && (
                  <Tooltip title={t('Navigate to draft')}>
                    <span>
                      <IconButton
                        color="primary"
                        onClick={() => navigateToDraft(work.draft_context)}
                        size="small"
                      >
                        <ArchitectureOutlined fontSize="small" />
                      </IconButton>
                    </span>
                  </Tooltip>
                )}
                <Tooltip title={!isCurrentContextWork ? t('Not available in draft') : t('Delete')}>
                  <span>
                    <IconButton
                      onClick={() => isCurrentContextWork && handleDelete(work.id)}
                      disabled={work.status === 'deleting'}
                      size="small"
                    >
                      <DeleteOutlined fontSize="small" color={isCurrentContextWork ? 'primary' : 'disabled'} />
                    </IconButton>
                  </span>
                </Tooltip>
              </ListItem>
            </Tooltip>
          );
        })}
      <DeleteDialog
        deletion={deletion}
        submitDelete={deleteWork}
        message={t_i18n('Do you want to delete this job?')}
      />
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
        draft_context
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(FileWork);
