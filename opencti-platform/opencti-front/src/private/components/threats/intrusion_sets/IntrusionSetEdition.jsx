import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
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
    const { t, intrusionSetId } = this.props;
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
                controlledDial={({ onOpen }) => (
                  <Button
                    style={{
                      marginLeft: '3px',
                      fontSize: 'small',
                    }}
                    variant='outlined'
                    onClick={onOpen}
                  >
                    {t('Edit')} <Create />
                  </Button>
                )}
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

export default compose(inject18n)(IntrusionSetEdition);
