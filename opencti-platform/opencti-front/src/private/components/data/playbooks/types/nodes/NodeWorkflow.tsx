import React, { memo, useState } from 'react';
import { Handle, Position, NodeProps, useReactFlow } from 'reactflow';
import { makeStyles } from '@mui/styles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import ItemIcon from '../../../../../../components/ItemIcon';
import { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';

type node = {
  id: string;
};

const useStyles = makeStyles<Theme>((theme) => ({
  node: {
    position: 'relative',
    border:
      theme.palette.mode === 'dark'
        ? '1px solid rgba(255, 255, 255, 0.12)'
        : '1px solid rgba(0, 0, 0, 0.12)',
    borderRadius: 4,
    backgroundColor: theme.palette.background.paper,
    width: 160,
    height: 50,
    padding: '8px 5px 5px 5px',
  },
  name: {
    maxWidth: 100,
    fontSize: 11,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  component: {
    maxWidth: 100,
    color:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, 0.5)'
        : 'rgba(0, 0, 0, 0.5)',
    fontSize: 9,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  handlesWrapper: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    width: '100%',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
  },
  handle: {
    position: 'relative',
    transform: 'none',
    left: 'auto',
    margin: '0 20px 0 20px',
  },
}));

const NodeWorkflow = ({ id, data }: NodeProps) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const { getNode } = useReactFlow();
  return (
    <div className={classes.node}>
      <ItemIcon type={data.component.icon} variant="inline" />
      <div style={{ float: 'left' }}>
        <div className={classes.name}>{data.name}</div>
        <div className={classes.component}>{data.component.name}</div>
      </div>
      <div style={{ float: 'right', margin: '-10px -4px 0 0' }}>
        <IconButton
          onClick={(event) => setAnchorEl(event.currentTarget)}
          aria-haspopup="true"
          size="small"
        >
          <MoreVert style={{ fontSize: 12 }} />
        </IconButton>
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={() => setAnchorEl(null)}
        >
          <MenuItem
            onClick={() => {
              data.openConfig(getNode(id));
              setAnchorEl(null);
            }}
          >
            {t('Update')}
          </MenuItem>
          <MenuItem
            onClick={() => {
              data.openDelete(getNode(id));
              setAnchorEl(null);
            }}
          >
            {t('Delete')}
          </MenuItem>
        </Menu>
      </div>
      <div className="clearfix" />
      {!data.component?.is_entry_point && (
        <Handle type="target" position={Position.Top} isConnectable={false} />
      )}
      <div className={classes.handlesWrapper}>
        {(data.component?.ports ?? []).map((n: node) => (
          <Handle
            id={n.id}
            type="source"
            position={Position.Bottom}
            isConnectable={false}
            className={classes.handle}
          />
        ))}
      </div>
    </div>
  );
};

export default memo(NodeWorkflow);
