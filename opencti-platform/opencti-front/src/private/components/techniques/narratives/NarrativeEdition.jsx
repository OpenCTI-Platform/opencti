import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import { Create } from '@mui/icons-material';
import { Button } from '@mui/material';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import NarrativeEditionContainer from './NarrativeEditionContainer';
import { narrativeEditionOverviewFocus } from './NarrativeEditionOverview';
import Loader from '../../../../components/Loader';

export const narrativeEditionQuery = graphql`
  query NarrativeEditionContainerQuery($id: String!) {
    narrative(id: $id) {
      ...NarrativeEditionContainer_narrative
    }
  }
`;

class NarrativeEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: narrativeEditionOverviewFocus,
      variables: {
        id: this.props.narrativeId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { t, narrativeId } = this.props;
    return (
      <QueryRenderer
        query={narrativeEditionQuery}
        variables={{ id: narrativeId }}
        render={({ props }) => {
          if (props) {
            return (
              <NarrativeEditionContainer
                narrative={props.narrative}
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

NarrativeEdition.propTypes = {
  narrativeId: PropTypes.string,
  me: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
)(NarrativeEdition);
