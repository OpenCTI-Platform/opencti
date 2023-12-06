import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { Button } from '@mui/material';
import { compose } from 'ramda';
import { Create } from '@mui/icons-material';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import SectorEditionContainer from './SectorEditionContainer';
import { sectorEditionOverviewFocus } from './SectorEditionOverview';
import Loader from '../../../../components/Loader';
import inject18n from '../../../../components/i18n';

export const sectorEditionQuery = graphql`
  query SectorEditionContainerQuery($id: String!) {
    sector(id: $id) {
      ...SectorEditionContainer_sector
    }
  }
`;

class SectorEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: sectorEditionOverviewFocus,
      variables: {
        id: this.props.sectorId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { t, sectorId } = this.props;
    return (
      <QueryRenderer
        query={sectorEditionQuery}
        variables={{ id: sectorId }}
        render={({ props }) => {
          if (props) {
            return (
              <SectorEditionContainer
                sector={props.sector}
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

SectorEdition.propTypes = {
  sectorId: PropTypes.string,
};

export default compose(inject18n)(SectorEdition);
