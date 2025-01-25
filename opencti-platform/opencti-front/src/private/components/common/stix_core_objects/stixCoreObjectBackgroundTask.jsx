import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const StixCoreObjectBackgroundTaskQuery = graphql`
    query stixCoreObjectBackgroundTaskQuery($id: ID!) {
        stixCoreBackgroundActiveOperations(id: $id) {
            id
            actions {
                type
            }
        }
    }
`;
const StixCoreObjectBackgroundTask = ({ id }) => {
  const { stixCoreBackgroundActiveOperations } = useLazyLoadQuery(StixCoreObjectBackgroundTaskQuery, { id });
  if (stixCoreBackgroundActiveOperations.length > 0) {
    return <div style={{ display: 'flex', alignItems: 'center', border: '1px solid #eeeeee', paddingRight: 30 }}>
      <Loader variant={LoaderVariant.inline} withRightPadding={false} />
      <div>
        {stixCoreBackgroundActiveOperations
          .map((task) => task.actions).flat()
          .map((op) => op.type)
          .map((type) => <div key={type}>{type}</div>)
        }
      </div>
    </div>;
  }
  return <></>;
};
export default StixCoreObjectBackgroundTask;
