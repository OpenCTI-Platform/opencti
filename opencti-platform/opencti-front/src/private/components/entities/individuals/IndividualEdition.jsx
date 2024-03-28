import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { Create } from '@mui/icons-material';
import { Button } from '@mui/material';
import { compose } from 'ramda';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import IndividualEditionContainer from './IndividualEditionContainer';
import { individualEditionOverviewFocus } from './IndividualEditionOverview';
import Loader from '../../../../components/Loader';
import inject18n from '../../../../components/i18n';

export const individualEditionQuery = graphql`
  query IndividualEditionContainerQuery($id: String!) {
    individual(id: $id) {
      id
      ...IndividualEditionContainer_individual
    }
  }
`;

class IndividualEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: individualEditionOverviewFocus,
      variables: {
        id: this.props.individualId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { t, individualId } = this.props;
    return (
      <QueryRenderer
        query={individualEditionQuery}
        variables={{ id: individualId }}
        render={({ props }) => {
          if (props) {
            return (
              <IndividualEditionContainer
                individual={props.individual}
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

IndividualEdition.propTypes = {
  individualId: PropTypes.string,
};

export default compose(inject18n)(IndividualEdition);
