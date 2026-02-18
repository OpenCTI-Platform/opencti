import Workflow from './workflow/Workflow';
import { ReactFlowProvider } from 'reactflow';
import { ErrorBoundary } from '../../Error';
import { graphql } from 'react-relay';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SubTypeWorkflowDefinitionQuery } from './__generated__/SubTypeWorkflowDefinitionQuery.graphql';
import Loader from '../../../../components/Loader';
import { Suspense } from 'react';

export const workflowDefinitionQuery = graphql`
  query SubTypeWorkflowDefinitionQuery($entityType: String!) {
    workflowDefinition(entityType: $entityType) {
      id
      name
      initialState
      states {
        name
        onExit{
          params
        }
        onEnter {
          params
        }
      }
      transitions {
        event
        from
        to
        actions {
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
  }
`;

const SubTypeWorkflow = () => {
  const queryRef = useQueryLoading<SubTypeWorkflowDefinitionQuery>(workflowDefinitionQuery, {
    entityType: 'DraftWorkspace',
  });

  return queryRef ? (
    <Suspense fallback={<Loader />}>

      <ErrorBoundary>
        <div style={{ width: '100%', height: 'calc(100vh - 250px)', marginBottom: '-50px' }}>
          <ReactFlowProvider>
            <Workflow queryRef={queryRef} />
          </ReactFlowProvider>
        </div>
      </ErrorBoundary>
    </Suspense>
  ) : <Loader />;
};

export default SubTypeWorkflow;
