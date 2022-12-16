import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../../../components/i18n';
import { QueryRenderer } from '../../../../../relay/environment';
import TaskEntityEditionContainer from './TaskEntityEditionContainer';
import { toastGenericError } from '../../../../../utils/bakedToast';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  menuItem: {
    padding: '15px 0',
    width: '152px',
    margin: '0 20px',
    justifyContent: 'center',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const taskEntityEditionQuery = graphql`
  query TaskEntityEditionQuery($id: ID!) {
    oscalTask(id: $id) {
      __typename
      id
      created
      modified
      name
      description
      links {
        __typename
        id
        source_name
        description
        entity_type
        url
        hashes {
          value
        }
        external_id
      }
      remarks {
        __typename
        id
        entity_type
        abstract
        content
        authors
      }
      related_tasks {
        id
        name
      }
      associated_activities {
        id
        entity_type
      }
    }
  }
`;

class TaskEntityEdition extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
    };
  }

  render() {
    const {
      classes, displayEdit, handleDisplayEdit, history, taskId,
    } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={taskEntityEditionQuery}
          variables={{ id: taskId }}
          render={({ error, props, retry }) => {
            if (error) {
              toastGenericError('Failed to edit Task');
            }
            if (props) {
              return (
                <TaskEntityEditionContainer
                  displayEdit={displayEdit}
                  history={history}
                  task={props.oscalTask}
                  refreshQuery={retry}
                  handleDisplayEdit={handleDisplayEdit}
                />
              );
            }
            return <></>;
          }}
        />
      </div>
    );
  }
}

TaskEntityEdition.propTypes = {
  roldId: PropTypes.string,
  displayEdit: PropTypes.bool,
  handleDisplayEdit: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(TaskEntityEdition);
