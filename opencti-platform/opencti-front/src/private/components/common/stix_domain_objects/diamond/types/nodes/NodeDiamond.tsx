import React, { memo } from 'react';
import { Handle, Position, NodeProps } from 'reactflow';
import makeStyles from '@mui/styles/makeStyles';
import type { Theme } from '../../../../../../../components/Theme';
import ItemIcon from '../../../../../../../components/ItemIcon';
import { truncate } from '../../../../../../../utils/String';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  node: {
    position: 'relative',
    width: 200,
    height: 200,
    lineHeight: '200px',
    whiteSpace: 'nowrap',
    textAlign: 'center',
    fontSize: 10,
    margin: 10,
    '&::before': {
      position: 'absolute',
      content: '""',
      top: 0,
      left: 0,
      height: '100%',
      width: '100%',
      transform: 'rotate(45deg)',
      boxShadow: '0px 0px 12px gray',
    },
    '&::after': {
      position: 'absolute',
      content: '""',
      top: 10,
      left: 10,
      height: 'calc(100% - 22px)', /* -22px is 2 * 10px gap on either side - 2px border on either side */
      width: 'calc(100% - 22px)', /* -22px is 2 * 10px gap on either side - 2px border on either side */
      border: `1px solid ${theme.palette.primary.main}`,
      transform: 'rotate(45deg)',
    },
  },
  handleTop: {
    top: -50,
  },
  handleRight: {
    right: -50,
  },
  handleBottom: {
    bottom: -50,
  },
  handleLeft: {
    left: -50,
  },
  adversary: {
    position: 'absolute',
    top: -85,
    left: 81,
  },
  infrastructure: {
    position: 'absolute',
    top: 10,
    right: -5,
  },
  victimology: {
    position: 'absolute',
    top: 110,
    left: 81,
  },
  capabilities: {
    position: 'absolute',
    top: 10,
    left: -5,
  },
}));

const NodeDiamond = ({ data }: NodeProps) => {
  const classes = useStyles();
  return (
    <div className={classes.node}>
      {truncate(data.name, 25, false)}
      <div className={classes.adversary}>
        {/* <ItemIcon type="threats" color="inherit" /> */}
        <ItemIcon type="threats" />
      </div>
      <div className={classes.infrastructure}>
        {/* <ItemIcon type="Infrastructure" color="inherit" /> */}
        <ItemIcon type="Infrastructure" />
      </div>
      <div className={classes.victimology}>
        {/* <ItemIcon type="victimology" color="inherit" /> */}
        <ItemIcon type="victimology" />
      </div>
      <div className={classes.capabilities}>
        {/* <ItemIcon type="Attack-Pattern" color="inherit" /> */}
        <ItemIcon type="Attack-Pattern" />
      </div>
      <Handle
        id="adversary"
        className={classes.handleTop}
        type="source"
        position={Position.Top}
        isConnectable={false}
      />
      <Handle
        id="infrastructure"
        className={classes.handleRight}
        type="source"
        position={Position.Right}
        isConnectable={false}
      />
      <Handle
        id="victimology"
        className={classes.handleBottom}
        type="source"
        position={Position.Bottom}
        isConnectable={false}
      />
      <Handle
        id="capabilities"
        className={classes.handleLeft}
        type="source"
        position={Position.Left}
        isConnectable={false}
      />
    </div>
  );
};

export default memo(NodeDiamond);
