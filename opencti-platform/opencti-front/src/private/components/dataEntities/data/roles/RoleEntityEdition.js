import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Menu from '@material-ui/core/Menu';
import Slide from '@material-ui/core/Slide';
import { MoreVertOutlined } from '@material-ui/icons';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../../relay/environment';
import RoleEntityEditionContainer from './RoleEntityEditionContainer';
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

const roleEntityEditionQuery = graphql`
  query RoleEntityEditionQuery($id: ID!) {
    oscalRole(id: $id) {
      id
      entity_type
      created
      modified
      role_identifier
      name
      short_name
      description
    }
  }
`;

class RoleEntityEdition extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
    };
  }

  render() {
    const {
      classes, t, displayEdit, handleDisplayEdit, history, responsibilityId,
    } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={roleEntityEditionQuery}
          variables={{ id: responsibilityId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              toastGenericError('Failed to edit Responsibility');
            }
            if (props) {
              return (
                <RoleEntityEditionContainer
                  displayEdit={displayEdit}
                  history={history}
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

RoleEntityEdition.propTypes = {
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
)(RoleEntityEdition);
