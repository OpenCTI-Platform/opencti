import { graphql, useFragment } from 'react-relay';
import { StixCoreObjectHistoryLine_node$key } from './__generated__/StixCoreObjectHistoryLine_node.graphql';
import HistoryLineContent from '../history/HistoryLineContent';

export const StixCoreObjectHistoryFragment = graphql`
  fragment StixCoreObjectHistoryLine_node on Log @argumentDefinitions(
    tz: {
      type: "String",
      defaultValue: null
    }
    locale: {
      type: "String",
      defaultValue: null
    }
    unit_system: {
      type: "String",
      defaultValue: null
    }
  ) {
    id
    event_type
    event_scope
    timestamp
    user {
      name
    }
    context_data(tz: $tz, locale: $locale, unit_system: $unit_system) {
      message
      commit
      to_id
      from_id
      external_references {
        id
        source_name
        external_id
        url
        description
      }
    }
  }
`;

interface StixCoreObjectHistoryLineProps {
  node: StixCoreObjectHistoryLine_node$key;
  isRelation: boolean;
}

const StixCoreObjectHistoryLine = ({ node, isRelation }: StixCoreObjectHistoryLineProps) => {
  const data = useFragment<StixCoreObjectHistoryLine_node$key>(StixCoreObjectHistoryFragment, node);

  return (
    <HistoryLineContent
      data={{
        eventScope: data.event_scope,
        timestamp: data.timestamp,
        userName: data.user?.name,
        message: data.context_data?.message,
        commit: data.context_data?.commit,
        externalReferences: data.context_data?.external_references ?? [],
      }}
      isRelation={isRelation}
    />
  );
};

export default StixCoreObjectHistoryLine;
