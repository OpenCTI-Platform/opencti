import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { Create } from '@mui/icons-material';
import { Button } from '@mui/material';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import AttackPatternEditionContainer from './AttackPatternEditionContainer';
import { attackPatternEditionOverviewFocus } from './AttackPatternEditionOverview';
import Loader from '../../../../components/Loader';

export const attackPatternEditionQuery = graphql`
  query AttackPatternEditionContainerQuery($id: String!) {
    attackPattern(id: $id) {
      ...AttackPatternEditionContainer_attackPattern
      ...AttackPatternEditionDetails_attackPattern
    }
  }
`;

class AttackPatternEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: attackPatternEditionOverviewFocus,
      variables: {
        id: this.props.attackPatternId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { t, attackPatternId } = this.props;
    return (
      <QueryRenderer
        query={attackPatternEditionQuery}
        variables={{ id: attackPatternId }}
        render={({ props }) => {
          if (props) {
            return (
              <AttackPatternEditionContainer
                attackPattern={props.attackPattern}
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

AttackPatternEdition.propTypes = {
  attackPatternId: PropTypes.string,
};

export default compose(inject18n)(AttackPatternEdition);
