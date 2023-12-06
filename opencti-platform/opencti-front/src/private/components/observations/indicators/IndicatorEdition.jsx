import React from 'react';
import { graphql } from 'react-relay';
import { Create } from '@mui/icons-material';
import { Button } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
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
  const { t_i18n } = useFormatter();
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
              controlledDial={({ onOpen }) => (
                <Button
                  onClick={onOpen}
                  variant='outlined'
                  style={{
                    marginLeft: '3px',
                    fontSize: 'small',
                  }}
                >
                  {t_i18n('Edit')} <Create />
                </Button>
              )}
            />
          );
        }
        return <Loader variant="inElement" />;
      }}
    />
  );
};

export default IndicatorEdition;
