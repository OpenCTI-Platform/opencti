import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { Create } from '@mui/icons-material';
import { Button } from '@mui/material';
import { compose } from 'ramda';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import SystemEditionContainer from './SystemEditionContainer';
import { systemEditionOverviewFocus } from './SystemEditionOverview';
import Loader from '../../../../components/Loader';
import inject18n from '../../../../components/i18n';

export const systemEditionQuery = graphql`
  query SystemEditionContainerQuery($id: String!) {
    system(id: $id) {
      ...SystemEditionContainer_system
    }
  }
`;

class SystemEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: systemEditionOverviewFocus,
      variables: {
        id: this.props.systemId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { t, systemId } = this.props;
    return (
      <QueryRenderer
        query={systemEditionQuery}
        variables={{ id: systemId }}
        render={({ props }) => {
          if (props) {
            return (
              <SystemEditionContainer
                system={props.system}
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

SystemEdition.propTypes = {
  systemId: PropTypes.string,
};

export default compose(inject18n)(SystemEdition);
