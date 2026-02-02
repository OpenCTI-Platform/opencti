import { FunctionComponent, ReactNode } from 'react';
import Button from '@common/button/Button';
import { Link } from 'react-router-dom';
import { Handle, Position } from 'reactflow';
import { useFormatter } from 'src/components/i18n';
import Card from '../../../../../../../components/common/card/Card';

interface NodeContainerProps {
  children: ReactNode;
  link: string;
  position: Position;
}

const NodeContainer: FunctionComponent<NodeContainerProps> = ({
  children,
  link,
  position,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Card
      sx={{
        position: 'relative',
        width: '400px',
      }}
    >
      <div>{children}</div>
      <Button
        sx={{ mt: 2 }}
        component={Link}
        to={link}
        size="small"
        variant="secondary"
        className="nodrag nopan"
      >
        {t_i18n('View all')}
      </Button>
      <Handle
        style={{ visibility: 'hidden' }}
        type="target"
        position={position}
        isConnectable={false}
      />
    </Card>
  );
};

export default NodeContainer;
