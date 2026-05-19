import { graphql, useFragment } from 'react-relay';
import { StixCoreRelationshipHistoryLine_node$key } from './__generated__/StixCoreRelationshipHistoryLine_node.graphql';
import HistoryLineContent from '../history/HistoryLineContent';

export const StixCoreRelationshipHistoryFragment = graphql`
  fragment StixCoreRelationshipHistoryLine_node on Log @argumentDefinitions(
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

interface StixCoreRelationshipHistoryLineProps {
  nodeRef: StixCoreRelationshipHistoryLine_node$key;
  isRelation: boolean;
}

const StixCoreRelationshipHistoryLine = ({ nodeRef, isRelation }: StixCoreRelationshipHistoryLineProps) => {
  const node = useFragment<StixCoreRelationshipHistoryLine_node$key>(StixCoreRelationshipHistoryFragment, nodeRef);

  return (
    <HistoryLineContent
      data={{
        eventScope: node.event_scope,
        timestamp: node.timestamp,
        userName: node.user?.name,
        message: node.context_data?.message,
        commit: node.context_data?.commit,
        externalReferences: node.context_data?.external_references ?? [],
      }}
      isRelation={isRelation}
    />
  );
};

export default StixCoreRelationshipHistoryLine;
