import Workflow from './workflow/Workflow';
import { ReactFlowProvider } from 'reactflow';
import { ErrorBoundary } from '../../Error';
import { graphql } from 'react-relay';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SubTypeWorkflowQuery } from './__generated__/SubTypeWorkflowQuery.graphql';
import Loader from '../../../../components/Loader';
import { Suspense } from 'react';

export const workflowQuery = graphql`
  query SubTypeWorkflowQuery($entityType: String!) {
    workflowDefinition(entityType: $entityType) {
      id
      name
      initialState
      states {
        statusId
        onExit{
          type
          mode
          params
        }
        onEnter {
          type
          mode
          params
        }
      }
      transitions {
        event
        from
        to
        actions {
          type
          mode
          params
        }
        conditions {
          type
          field
          operator
          value
        }
        
      }
    }
    members(search: "", first: 100) {
      edges {
        node {
          id
          entity_type
          name
        }
      }
    }
    statusTemplates(search: "") {
      edges {
        node {
          id
          name
          color
        }
      }
    }
  }
`;

const SubTypeWorkflow = () => {
  const workflowQueryRef = useQueryLoading<SubTypeWorkflowQuery>(
    workflowQuery,
    { entityType: 'DraftWorkspace' },
  );

  if (!workflowQueryRef) {
    return <Loader />;
  }

  return (
    <Suspense fallback={<Loader />}>
      <ErrorBoundary>
        <div style={{ width: '100%', height: 'calc(100vh - 250px)', marginBottom: '-50px' }}>
          <ReactFlowProvider>
            <Workflow
              queryRef={workflowQueryRef}
            />
          </ReactFlowProvider>
        </div>
      </ErrorBoundary>
    </Suspense>
  );
};

export default SubTypeWorkflow;
