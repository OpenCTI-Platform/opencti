import React, { Component } from 'react';
import * as PropTypes from 'prop-types'
import uuid from 'uuid/v4';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core';
import CircularProgress from '@material-ui/core/CircularProgress';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { CheckCircle, Warning } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  nested: {
    paddingLeft: theme.spacing(4),
  },
});

class FileWorkComponent extends Component {
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
                  <Warning
                    style={{ fontSize: 10, marginRight: 10, color: 'red' }}
                  />
                )}
                {work.status === 'complete' && (
                  <CheckCircle
                    style={{ fontSize: 10, marginRight: 10, color: 'green' }}
                  />
                )}
                {work.status === 'progress' && (
                  <CircularProgress
                    size={25}
                    thickness={2}
                    style={{ marginRight: 10 }}
                  />
                )}
              </ListItemIcon>
              <ListItemText
                primary={work.connector.name}
                secondary={t(work.status)}
              />
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
