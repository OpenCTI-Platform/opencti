import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  propOr, compose, last, join,
} from 'ramda';
import { v4 as uuid } from 'uuid';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core';
import CircularProgress from '@material-ui/core/CircularProgress';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import {
  CheckCircleOutlined,
  DeleteOutlined,
  WarningOutlined,
} from '@material-ui/icons';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
import Tooltip from '@material-ui/core/Tooltip';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

const styles = (theme) => ({
  nested: {
    paddingLeft: theme.spacing(4),
  },
});

const fileWorkDeleteMutation = graphql`
  mutation FileWorkDeleteMutation($workId: ID!) {
    deleteWork(id: $workId)
  }
`;

class FileWorkComponent extends Component {
  deleteWork(workId) {
    commitMutation({
      mutation: fileWorkDeleteMutation,
      variables: { workId },
    });
  }

  render() {
    const {
      t,
      nsdt,
      classes,
      file: { works },
    } = this.props;
    return (
      <List component="div" disablePadding={true}>
        {works
          && works.map((work) => {
            const message = join(
              ' | ',
              propOr([], 'messages', last(propOr([], 'jobs', work))),
            );
            return (
              <Tooltip title={message} key={uuid()}>
                <ListItem
                  dense={true}
                  button={true}
                  divider={true}
                  classes={{ root: classes.nested }}
                >
                  <ListItemIcon>
                    {(work.status === 'error' || work.status === 'partial') && (
                      <WarningOutlined
                        style={{ fontSize: 15, color: '#f44336' }}
                      />
                    )}
                    {work.status === 'complete' && (
                      <CheckCircleOutlined
                        style={{ fontSize: 15, color: '#4caf50' }}
                      />
                    )}
                    {work.status === 'progress' && (
                      <CircularProgress
                        size={20}
                        thickness={2}
                        style={{ marginRight: 10 }}
                      />
                    )}
                  </ListItemIcon>
                  <ListItemText
                    primary={propOr(t('Deleted'), 'name', work.connector)}
                    secondary={nsdt(work.created_at)}
                  />
                  <ListItemSecondaryAction style={{ right: 0 }}>
                    <IconButton onClick={this.deleteWork.bind(this, work.id)}>
                      <DeleteOutlined color="primary" />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              </Tooltip>
            );
          })}
      </List>
    );
  }
}

FileWorkComponent.propTypes = {
  classes: PropTypes.object,
  file: PropTypes.object.isRequired,
  nsdt: PropTypes.func,
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
        jobs {
          created_at
          messages
        }
        status
        work_type
        created_at
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(FileWork);
