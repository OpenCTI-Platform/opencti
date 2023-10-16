import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import IntrusionSetEditionContainer from './IntrusionSetEditionContainer';
import { intrusionSetEditionOverviewFocus } from './IntrusionSetEditionOverview';
import Loader from '../../../../components/Loader';

export const intrusionSetEditionQuery = graphql`
  query IntrusionSetEditionContainerQuery($id: String!) {
    intrusionSet(id: $id) {
      ...IntrusionSetEditionContainer_intrusionSet
    }
  }
`;

class IntrusionSetEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: intrusionSetEditionOverviewFocus,
      variables: {
        id: this.props.intrusionSetId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { intrusionSetId } = this.props;
    return (
      <QueryRenderer
        query={intrusionSetEditionQuery}
        variables={{ id: intrusionSetId }}
        render={({ props }) => {
          if (props) {
            return (
              <IntrusionSetEditionContainer
                intrusionSet={props.intrusionSet}
                handleClose={this.handleClose.bind(this)}
              />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    );
  }
}

IntrusionSetEdition.propTypes = {
  intrusionSetId: PropTypes.string,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
)(IntrusionSetEdition);
