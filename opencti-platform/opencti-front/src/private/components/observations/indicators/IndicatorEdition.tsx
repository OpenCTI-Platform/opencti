import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import IndicatorEditionContainer from './IndicatorEditionContainer';
import { indicatorEditionOverviewFocus } from './IndicatorEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import { IndicatorEditionContainerQuery$data } from '@components/observations/indicators/__generated__/IndicatorEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const indicatorEditionQuery = graphql`
  query IndicatorEditionContainerQuery($id: String!) {
    indicator(id: $id) {
      ...IndicatorEditionContainer_indicator
    }
  }
`;

interface IndicatorEditionProps {
  indicatorId: string;
}

const IndicatorEdition: FunctionComponent<IndicatorEditionProps> = ({
  indicatorId,
}) => {
  const [commit] = useApiMutation(indicatorEditionOverviewFocus);

  const handleClose = () => {
    commit({
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
      render={({ props }: { props: IndicatorEditionContainerQuery$data }) => {
        if (props && props.indicator) {
          return (
            <IndicatorEditionContainer
              indicator={props.indicator}
              handleClose={handleClose}
              controlledDial={EditEntityControlledDial}
            />
          );
        }
        return <Loader variant={LoaderVariant.inline} />;
      }}
    />
  );
};

export default IndicatorEdition;
