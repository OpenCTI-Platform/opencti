import React, { memo } from 'react';
import { Handle, NodeProps, useReactFlow } from 'reactflow';
import { styled, useTheme } from '@mui/material/styles';
import { AddOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../../components/i18n';
import type { Theme } from '../../../../../../components/Theme';
import { usePlaybookHandlePositions } from '../../hooks/usePlaybookLayoutMode';
import { PLAYBOOK_PORT_ADD } from './playbookNodeGeometry';

const HiddenHandle = styled(Handle)({
  visibility: 'hidden',
});

// A free out port: a small dashed "+" next to the port. An empty playbook: one wide call to action.
const NodePlaceholder = ({ id, data }: NodeProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { getNode } = useReactFlow();
  const { target, source } = usePlaybookHandlePositions();
  const isOrigin = Boolean(data.component?.is_entry_point);
  const label = isOrigin ? t_i18n('Add an entry point') : t_i18n('Add component');
  const handles = (
    <>
      <HiddenHandle type="target" position={target} isConnectable={false} />
      <HiddenHandle type="source" position={source} isConnectable={false} />
    </>
  );
  if (isOrigin) {
    return (
      <span style={{ display: 'inline-flex', position: 'relative' }}>
        <Button
          aria-label={label}
          onClick={() => data.openConfig(getNode(id))}
          startIcon={<AddOutlined />}
        >
          {label}
        </Button>
        {handles}
      </span>
    );
  }
  return (
    <span
      data-testid={`playbook-add-${id}`}
      style={{
        position: 'relative',
        width: PLAYBOOK_PORT_ADD.size,
        height: PLAYBOOK_PORT_ADD.size,
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        borderRadius: '50%',
        backgroundColor: theme.palette.background.paper,
        border: `1px dashed ${theme.palette.primary.main}`,
      }}
    >
      <IconButton
        aria-label={label}
        tooltip={label}
        size="small"
        onClick={() => data.openConfig(getNode(id))}
      >
        <AddOutlined style={{ fontSize: 16 }} />
      </IconButton>
      {handles}
    </span>
  );
};

export default memo(NodePlaceholder);
