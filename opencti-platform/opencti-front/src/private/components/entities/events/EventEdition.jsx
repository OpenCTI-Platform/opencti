import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import EventEditionContainer from './EventEditionContainer';
import { eventEditionOverviewFocus } from './EventEditionOverview';
import Loader from '../../../../components/Loader';

export const eventEditionQuery = graphql`
  query EventEditionContainerQuery($id: String!) {
    event(id: $id) {
      ...EventEditionContainer_event
    }
  }
`;

class EventEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    commitMutation({
      mutation: eventEditionOverviewFocus,
      variables: {
        id: this.props.eventId,
        input: { focusOn: '' },
      },
    });
    this.setState({ open: false });
  }

  render() {
    const { eventId } = this.props;
    return (
      <QueryRenderer
        query={eventEditionQuery}
        variables={{ id: eventId }}
        render={({ props }) => {
          if (props) {
            return (
              <EventEditionContainer event={props.event} handleClose={this.handleClose.bind(this)} />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    );
  }
}

EventEdition.propTypes = {
  eventId: PropTypes.string,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
)(EventEdition);
