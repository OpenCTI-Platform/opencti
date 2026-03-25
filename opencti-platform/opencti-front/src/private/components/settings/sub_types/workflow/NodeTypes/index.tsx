import StatusNode from './StatusNode';
import TransitionNode from './TransitionNode';
import PlaceholderNode from './PlaceholderNode';

export const nodeTypes = {
  status: StatusNode,
  transition: TransitionNode,
  placeholder: PlaceholderNode,
};

export default nodeTypes;
