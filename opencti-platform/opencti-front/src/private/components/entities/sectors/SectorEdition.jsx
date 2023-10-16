import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import SectorEditionContainer from './SectorEditionContainer';
import { sectorEditionOverviewFocus } from './SectorEditionOverview';
import Loader from '../../../../components/Loader';

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
    const { sectorId } = this.props;
    return (
      <QueryRenderer
        query={sectorEditionQuery}
        variables={{ id: sectorId }}
        render={({ props }) => {
          if (props) {
            return (
              <SectorEditionContainer sector={props.sector} handleClose={this.handleClose.bind(this)} />
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

export default SectorEdition;
