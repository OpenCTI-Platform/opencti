import React, { memo } from 'react';
import { Handle, Position, NodeProps, useReactFlow } from 'reactflow';
import { styled } from '@mui/material/styles';
import Button from '@common/button/Button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../../../components/i18n';

// Only the geometry: the tone is the library's own primary button.
const PlaceholderButton = styled(Button)({
  '&&': {
    width: 160,
    height: 50,
    padding: 0,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
});

const HiddenHandle = styled(Handle)({
  visibility: 'hidden',
});

const NodePlaceholder = ({ id, data }: NodeProps) => {
  const { t_i18n } = useFormatter();
  const { getNode } = useReactFlow();
  return (
    <Tooltip>
      {/* The wrapper carries the ref: the shared Button does not forward one. */}
      <TooltipTrigger asChild>
        <span style={{ display: 'inline-flex' }}>
          <PlaceholderButton
            aria-label={t_i18n('Add component')}
            onClick={() => data.openConfig(getNode(id))}
          >
            {data.name}
            <HiddenHandle
              type="target"
              position={Position.Top}
              isConnectable={false}
            />
            <HiddenHandle
              type="source"
              position={Position.Bottom}
              isConnectable={false}
            />
          </PlaceholderButton>
        </span>
      </TooltipTrigger>
      <TooltipContent>{t_i18n('Add component')}</TooltipContent>
    </Tooltip>
  );
};

export default memo(NodePlaceholder);
