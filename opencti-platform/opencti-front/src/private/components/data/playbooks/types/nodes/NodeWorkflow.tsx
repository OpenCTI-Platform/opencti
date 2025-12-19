import React, { memo, useState } from 'react';
import { Handle, Position, NodeProps, useReactFlow } from 'reactflow';
import { makeStyles } from '@mui/styles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { MoreVert, LoginOutlined } from '@mui/icons-material';
import ItemIcon from '../../../../../../components/ItemIcon';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';

type node = {
  id: string;
};

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
    fontSize: 10,
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
    fontSize: 8,
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
    position: 'absolute',
  },
}));

const getHandlePositionStyle = (count: number, index: number, width = 160): React.CSSProperties | undefined => {
  // we distribute evenly the output ports at the bottom using CSS
  // we divide our width in N intervals, the N points being at the center of their interval
  const interval = width / count;
  const position = index * interval + (interval / 2);
  return { left: position };
};

const NodeWorkflow = ({ id, data }: NodeProps) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const { getNode } = useReactFlow();
  return (
    <div className={classes.node}>
      <ItemIcon type={data.component.icon} variant="inline" />
      <div style={{ float: 'left' }}>
        <Tooltip title={t_i18n(data.name)}>
          <div className={classes.name}>{t_i18n(data.name)}</div>
        </Tooltip>
        <Tooltip title={t_i18n(data.component.description)}>
          <div className={classes.component}>{t_i18n(data.component.description)}</div>
        </Tooltip>
      </div>
      <div className="clearfix" />
      <div style={{ position: 'absolute', top: 0, right: 0 }}>
        <IconButton
          onClick={(event) => setAnchorEl(event.currentTarget)}
          aria-haspopup="true"
          size="small"
          color="primary"
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
            {t_i18n('Update')}
          </MenuItem>
          <MenuItem
            onClick={() => {
              data.openReplace(getNode(id));
              setAnchorEl(null);
            }}
          >
            {t_i18n('Replace')}
          </MenuItem>
          <MenuItem
            onClick={() => {
              data.openDelete(getNode(id));
              setAnchorEl(null);
            }}
          >
            {t_i18n('Delete')}
          </MenuItem>
        </Menu>
      </div>
      {!data.component?.is_entry_point && (
        <div style={{ position: 'absolute', bottom: 0, right: 0 }}>
          <Tooltip
            title={t_i18n(
              'Add a new branch at the same level from the parent output',
            )}
          >
            <IconButton
              onClick={() => data.openAddSibling(getNode(id))}
              aria-haspopup="true"
              size="small"
            >
              <LoginOutlined style={{ fontSize: 12 }} />
            </IconButton>
          </Tooltip>
        </div>
      )}
      {!data.component?.is_entry_point && (
        <Handle type="target" position={Position.Top} isConnectable={false} />
      )}
      <div className={classes.handlesWrapper}>
        {(data.component?.ports ?? []).map((n: node, index: number, array: node[]) => (
          <Handle
            key={n.id}
            id={n.id}
            type="source"
            position={Position.Bottom}
            isConnectable={false}
            className={classes.handle}
            style={getHandlePositionStyle(array.length, index)}
          />
        ))}
      </div>
    </div>
  );
};

export default memo(NodeWorkflow);
