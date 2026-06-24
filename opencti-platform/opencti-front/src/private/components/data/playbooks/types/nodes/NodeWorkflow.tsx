import React, { memo, useState } from 'react';
import { Handle, Position, NodeProps, useReactFlow } from 'reactflow';
import { useTheme } from '@mui/material/styles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { MoreVert, LoginOutlined } from '@mui/icons-material';
import ItemIcon from '../../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../../components/i18n';
import { truncate } from '../../../../../../utils/String';

type node = {
  id: string;
};

const getHandlePositionStyle = (count: number, index: number, width = 220): React.CSSProperties | undefined => {
  // we distribute evenly the output ports at the bottom using CSS
  // we divide our width in N intervals, the N points being at the center of their interval
  const interval = width / count;
  const position = index * interval + (interval / 2);
  return { left: position };
};

const NodeWorkflow = ({ id, data }: NodeProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const { getNode } = useReactFlow();
  const displayDescription = data.description || data.component?.description;
  return (
    <div style={{
      position: 'relative',
      border: theme.palette.mode === 'dark'
        ? '1px solid rgba(255, 255, 255, 0.12)'
        : '1px solid rgba(0, 0, 0, 0.12)',
      borderRadius: 4,
      backgroundColor: theme.palette.background.paper,
      width: 220,
      minHeight: 50,
      padding: '8px 5px 5px 5px',
    }}
    >
      <ItemIcon type={data.component.icon} variant="inline" />
      <div style={{ float: 'left' }}>
        <Tooltip title={t_i18n(data.name)}>
          <div style={{ maxWidth: 160, fontSize: 10, wordBreak: 'break-word' }}>
            {t_i18n(truncate(data.name, 100, false))}
          </div>
        </Tooltip>
        <Tooltip title={t_i18n(displayDescription)}>
          <div style={{
            maxWidth: 160,
            fontSize: 8,
            color: theme.palette.mode === 'dark'
              ? 'rgba(255, 255, 255, 0.5)'
              : 'rgba(0, 0, 0, 0.5)',
            wordBreak: 'break-word',
          }}
          >
            {t_i18n(truncate(displayDescription, 150, false))}
          </div>
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
      <div style={{
        position: 'absolute',
        bottom: 0,
        left: 0,
        width: '100%',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
      }}
      >
        {(data.component?.ports ?? []).map((n: node, index: number, array: node[]) => (
          <Handle
            key={n.id}
            id={n.id}
            type="source"
            position={Position.Bottom}
            isConnectable={false}
            style={{ ...getHandlePositionStyle(array.length, index), position: 'absolute' }}
          />
        ))}
      </div>
    </div>
  );
};

export default memo(NodeWorkflow);
