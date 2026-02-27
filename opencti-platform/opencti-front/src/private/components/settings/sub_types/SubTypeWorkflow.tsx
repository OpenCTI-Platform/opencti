import Workflow from './workflow/Workflow';
import { ReactFlowProvider } from 'reactflow';
import { ErrorBoundary } from '../../Error';
import { graphql } from 'react-relay';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SubTypeWorkflowDefinitionQuery } from './__generated__/SubTypeWorkflowDefinitionQuery.graphql';
import Loader from '../../../../components/Loader';
import { Suspense } from 'react';
import { StatusTemplateFieldQuery } from '@components/common/form/StatusTemplateField';
import { StatusTemplateFieldSearchQuery } from '@components/common/form/__generated__/StatusTemplateFieldSearchQuery.graphql';

export const workflowDefinitionQuery = graphql`
  query SubTypeWorkflowDefinitionQuery($entityType: String!) {
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
  }
`;

const SubTypeWorkflow = () => {
  const workflowQueryRef = useQueryLoading<SubTypeWorkflowDefinitionQuery>(
    workflowDefinitionQuery,
    { entityType: 'DraftWorkspace' },
  );

  const statusTemplatesQueryRef = useQueryLoading<StatusTemplateFieldSearchQuery>(
    StatusTemplateFieldQuery,
    {},
  );

  if (!workflowQueryRef || !statusTemplatesQueryRef) {
    return <Loader />;
  }

  return (
    <Suspense fallback={<Loader />}>
      <ErrorBoundary>
        <div style={{ width: '100%', height: 'calc(100vh - 250px)', marginBottom: '-50px' }}>
          <ReactFlowProvider>
            <Workflow
              queryRef={workflowQueryRef}
              statusTemplatesQueryRef={statusTemplatesQueryRef}
            />
          </ReactFlowProvider>
        </div>
      </ErrorBoundary>
    </Suspense>
  );
};

export default SubTypeWorkflow;
