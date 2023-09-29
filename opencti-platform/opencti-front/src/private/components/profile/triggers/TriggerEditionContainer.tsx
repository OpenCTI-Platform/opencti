import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import TriggerEditionOverview from './TriggerEditionOverview';
import { TriggerEditionContainerKnowledgeQuery } from './__generated__/TriggerEditionContainerKnowledgeQuery.graphql';

export const triggerKnowledgeEditionQuery = graphql`
  query TriggerEditionContainerKnowledgeQuery($id: String!) {
    triggerKnowledge(id: $id) {
      ...TriggerEditionOverview_trigger
    }
  }
`;

export const triggerActivityEditionQuery = graphql`
  query TriggerEditionContainerActivityQuery($id: String!) {
    triggerActivity(id: $id) {
      ...TriggerEditionOverview_trigger
    }
  }
`;

interface TriggerEditionContainerProps {
  handleClose: () => void;
  queryRef: PreloadedQuery<TriggerEditionContainerKnowledgeQuery>;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
}

const TriggerEditionContainer: FunctionComponent<TriggerEditionContainerProps> = ({ handleClose, queryRef, paginationOptions }) => {
  const queryData = usePreloadedQuery(triggerKnowledgeEditionQuery, queryRef);
  if (queryData.triggerKnowledge) {
    return (
      <TriggerEditionOverview
        data={queryData.triggerKnowledge}
        handleClose={handleClose}
        paginationOptions={paginationOptions}
      />
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default TriggerEditionContainer;
