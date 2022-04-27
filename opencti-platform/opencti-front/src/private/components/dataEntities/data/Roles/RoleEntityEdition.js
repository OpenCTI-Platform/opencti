import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Menu from '@material-ui/core/Menu';
import { QueryRenderer as QR } from 'react-relay';
import Slide from '@material-ui/core/Slide';
import { MoreVertOutlined } from '@material-ui/icons';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../../components/i18n';
import QueryRendererDarkLight from '../../../../../relay/environmentDarkLight';
import { commitMutation } from '../../../../../relay/environment';
// import StixCoreRelationshipEdition from './StixCoreRelationshipEdition';
import RoleEntityEditionContainer from './RoleEntityEditionContainer';

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

// const roleEntityEditionQuery = graphql`
//   query RoleEntityEditionQuery($id: ID!) {
//     riskResponse(id: $id) {
//       id
//       name                # Title
//       description         # Description
//       created             # Created
//       modified            # Last Modified
//       lifecycle           # Lifecycle
//       response_type       # Response Type
//       origins{            # Detection Source
//         id
//         origin_actors {
//           actor_type
//           actor_ref {
//             ... on Component {
//               id
//               component_type
//               name          # Source
//             }
//             ... on OscalParty {
//               id
//               party_type
//               name            # Source
//             }
//           }
//         }
//       }
//     }
//   }
// `;

class RoleEntityEdition extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
    };
  }

  render() {
    const {
      classes, t, displayEdit, handleDisplayEdit, history,
    } = this.props;
    return (
      <div className={classes.container}>
        {/* <QR
          environment={QueryRendererDarkLight}
          query={roleEntityEditionQuery}
          variables={{ id: cyioCoreRelationshipId }}
          render={({ error, props, retry }) => {
            if (props) {
              return ( */}
        <RoleEntityEditionContainer
          displayEdit={displayEdit}
          history={history}
          handleDisplayEdit={handleDisplayEdit}
        />
        {/* );
            }
            return <></>;
          }}
        /> */}
      </div>
    );
  }
}

RoleEntityEdition.propTypes = {
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
