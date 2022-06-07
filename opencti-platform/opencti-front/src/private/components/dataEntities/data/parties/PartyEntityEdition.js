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
import PartyEntityEditionContainer from './PartyEntityEditionContainer';
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

const partyEntityEditionQuery = graphql`
  query PartyEntityEditionQuery($id: ID!) {
    oscalParty(id: $id) {
      id
      name
      office
      created
      modified
      job_title
      mail_stop
      short_name
      party_type
      entity_type
      description
      email_addresses
      telephone_numbers {
        __typename
        id
        entity_type
        usage_type
        phone_number
      }
      external_identifiers {
        __typename
        id
        entity_type
        scheme
        identifier
      }
      addresses {
        __typename
        id
        entity_type
        address_type
        street_address
        city
        administrative_area
        country_code
        postal_code
      }
      locations {
        id
        name
        location_type
        location_class
        address {
          id
          address_type
          street_address
          city
          administrative_area
          country_code
          postal_code
        }
      }
      member_of_organizations {
        id
        name
      }
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
      classes, t, displayEdit, handleDisplayEdit, history, partyId,
    } = this.props;
    return (
      <div className={classes.container}>
        <QR
          environment={QueryRendererDarkLight}
          query={partyEntityEditionQuery}
          variables={{ id: partyId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              return toastGenericError('Failed to edit Party');
            }
            if (props) {
              return (
                <PartyEntityEditionContainer
                  displayEdit={displayEdit}
                  history={history}
                  party={props.oscalParty}
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
  partyId: PropTypes.string,
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
