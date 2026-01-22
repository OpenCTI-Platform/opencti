import React, { memo } from 'react';
import { NodeProps, Position } from 'reactflow';
import Typography from '@mui/material/Typography';

import NodeContainer from '@components/common/stix_domain_objects/diamond/types/nodes/NodeContainer';
import { useFormatter } from '../../../../../../../../components/i18n';
import { nodeAdversaryUtils } from './nodeAdversaryUtils';
import { emptyFilled } from '../../../../../../../../utils/String';

const NodeAdversary = ({ data }: NodeProps) => {
  const { entityLink, generatedFilters, aliases, isArsenal, lastAttributions } = nodeAdversaryUtils({ data });
  const { t_i18n } = useFormatter();
  return (
    <NodeContainer link={`${entityLink}/all?filters=${generatedFilters}&view=entities`} position={Position.Bottom} height={200}>
      <>
        <Typography variant="h3" gutterBottom>
          {t_i18n('Aliases')}
        </Typography>
        {emptyFilled(aliases)}
        <Typography variant="h3" gutterBottom sx={{ marginTop: '20px' }}>
          {isArsenal ? t_i18n('Last used by') : t_i18n('Last attributions')}
        </Typography>
        {lastAttributions}
      </>
    </NodeContainer>
  );
};

export default memo(NodeAdversary);
