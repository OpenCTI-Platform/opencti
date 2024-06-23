import { NodeTypes } from 'reactflow';

import NodeDiamond from './NodeDiamond';
import NodeCard from './NodeCard';
import NodeAdversary from './NodeAdversary';
import NodeVictimology from './NodeVictimology';
import NodeInfrastructure from './NodeInfrastructure';
import NodeCapabilities from './NodeCapabilities';

const nodeTypes: NodeTypes = {
  diamond: NodeDiamond,
  card: NodeCard,
  adversary: NodeAdversary,
  victimology: NodeVictimology,
  infrastructure: NodeInfrastructure,
  capabilities: NodeCapabilities,
};

export default nodeTypes;
