import { NodeTypes } from 'reactflow';

import PlaceholderNode from './PlaceholderNode';
import WorkflowNode from './WorkflowNode';

const nodeTypes: NodeTypes = {
  placeholder: PlaceholderNode,
  workflow: WorkflowNode,
};

export default nodeTypes;
