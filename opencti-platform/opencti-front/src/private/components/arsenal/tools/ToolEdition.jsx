import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import ToolEditionContainer from './ToolEditionContainer';
import { toolEditionOverviewFocus } from './ToolEditionOverview';
import Loader from '../../../../components/Loader';

export const toolEditionQuery = graphql`
  query ToolEditionContainerQuery($id: String!) {
    tool(id: $id) {
      ...ToolEditionContainer_tool
    }
  }
`;

class ToolEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: toolEditionOverviewFocus,
      variables: {
        id: this.props.toolId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { t, toolId } = this.props;
    return (
      <QueryRenderer
        query={toolEditionQuery}
        variables={{ id: toolId }}
        render={({ props }) => {
          if (props) {
            return (
              <ToolEditionContainer
                tool={props.tool}
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

ToolEdition.propTypes = {
  toolId: PropTypes.string,
  me: PropTypes.object,
  theme: PropTypes.object,
};

export default compose(inject18n)(ToolEdition);
