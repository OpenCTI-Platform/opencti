import { NodeTypes } from 'reactflow';

import NodePlaceholder from './NodePlaceholder';
import NodeWorkflow from './NodeWorkflow';

const nodeTypes: NodeTypes = {
  placeholder: NodePlaceholder,
  workflow: NodeWorkflow,
};

export default nodeTypes;
