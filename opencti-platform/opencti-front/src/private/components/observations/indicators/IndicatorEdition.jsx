import React from 'react';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import IndicatorEditionContainer from './IndicatorEditionContainer';
import { indicatorEditionOverviewFocus } from './IndicatorEditionOverview';
import Loader from '../../../../components/Loader';

export const indicatorEditionQuery = graphql`
  query IndicatorEditionContainerQuery($id: String!) {
    indicator(id: $id) {
      ...IndicatorEditionContainer_indicator
    }
  }
`;

const IndicatorEdition = ({ indicatorId }) => {
  const handleClose = () => {
    commitMutation({
      mutation: indicatorEditionOverviewFocus,
      variables: {
        id: indicatorId,
        input: { focusOn: '' },
      },
    });
  };

  return (
    <QueryRenderer
      query={indicatorEditionQuery}
      variables={{ id: indicatorId }}
      render={({ props }) => {
        if (props) {
          return (
            <IndicatorEditionContainer
              indicator={props.indicator}
              handleClose={handleClose}
            />
          );
        }
        return <Loader variant="inElement" />;
      }}
    />
  );
};

export default IndicatorEdition;
