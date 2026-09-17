import React, { memo } from 'react';
import { Handle, Position, NodeProps, useReactFlow } from 'reactflow';
import makeStyles from '@mui/styles/makeStyles';
import type { Theme } from '../../../../../../components/Theme';
import Button from '@common/button/Button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../../../components/i18n';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  // Only the geometry: the tone is the library's own primary button.
  node: {
    width: 160,
    height: 50,
    padding: 0,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  handle: {
    visibility: 'hidden',
  },
}));

const NodePlaceholder = ({ id, data }: NodeProps) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { getNode } = useReactFlow();
  return (
    <Tooltip>
      {/* The wrapper carries the ref: the shared Button does not forward one. */}
      <TooltipTrigger asChild>
        <span style={{ display: 'inline-flex' }}>
          <Button
            className={classes.node}
            aria-label={t_i18n('Add component')}
            onClick={() => data.openConfig(getNode(id))}
          >
            {data.name}
            <Handle
              className={classes.handle}
              type="target"
              position={Position.Top}
              isConnectable={false}
            />
            <Handle
              className={classes.handle}
              type="source"
              position={Position.Bottom}
              isConnectable={false}
            />
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>{t_i18n('Add component')}</TooltipContent>
    </Tooltip>
  );
};

export default memo(NodePlaceholder);
