import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import uuid from 'uuid/v4';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core';
import CircularProgress from '@material-ui/core/CircularProgress';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { CheckCircle, Delete, Warning } from '@material-ui/icons';
import { compose } from 'ramda';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
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
      classes,
      file: { works },
    } = this.props;
    return (
      <List component="div" disablePadding={true}>
        {works
          && works.map((work) => (
            <ListItem
              key={uuid()}
              dense={true}
              button={true}
              divider={true}
              classes={{ root: classes.nested }}
            >
              <ListItemIcon>
                {(work.status === 'error' || work.status === 'partial') && (
                  <Warning style={{ fontSize: 15, color: '#f44336' }} />
                )}
                {work.status === 'complete' && (
                  <CheckCircle style={{ fontSize: 15, color: '#4caf50' }} />
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
                primary={work.connector.name}
                secondary={t(work.status)}
              />
              <ListItemSecondaryAction style={{ right: 0 }}>
                <IconButton onClick={this.deleteWork.bind(this, work.id)}>
                  <Delete color="primary" />
                </IconButton>
              </ListItemSecondaryAction>
            </ListItem>
          ))}
      </List>
    );
  }
}

FileWorkComponent.propTypes = {
  classes: PropTypes.object,
  file: PropTypes.object.isRequired,
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

export default compose(
  inject18n,
  withStyles(styles),
)(FileWork);
