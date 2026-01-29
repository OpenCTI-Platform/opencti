import Workflow from './workflow/Workflow';
import { ReactFlowProvider } from 'reactflow';
import { ErrorBoundary } from '../../Error';

const SubTypeWorkflow = () => {
  // TODO use workflow data from subType
  // const { subType } = useOutletContext<{ subType: SubTypeQuery['response']['subType'] }>();
  return (
    // <div style={{ width: '100%', height: 'calc(100vh - 200px)' }}>
    <ErrorBoundary>
      <div style={{ width: '100%', height: 'calc(100vh - 250px)', marginBottom: '-50px' }}>
        <ReactFlowProvider>
          <Workflow />
        </ReactFlowProvider>
      </div>
    </ErrorBoundary>
    // </div>
  );
};

export default SubTypeWorkflow;
