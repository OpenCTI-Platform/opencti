import React, { memo } from 'react';
import * as R from 'ramda';
import { Handle, NodeProps, Position } from 'reactflow';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import { Link } from 'react-router-dom';
import getFilterFromEntityTypeAndNodeType, { DiamondNodeType } from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';
import { useTheme } from '@mui/styles';
import NodeContainer from '@components/common/stix_domain_objects/diamond/types/nodes/NodeContainer';
import type { Theme } from '../../../../../../../components/Theme';
import { useFormatter } from '../../../../../../../components/i18n';
import { emptyFilled } from '../../../../../../../utils/String';

const NodeCapabilities = ({ data }: NodeProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const { stixDomainObject, entityLink } = data;

  const usedAttackPatterns = R.uniq((stixDomainObject.attackPatternsUsed?.edges ?? [])
    .map((n: { node: { to: { name: string, x_mitre_id: string } } }) => (n?.node?.to?.x_mitre_id ? `[${n?.node?.to?.x_mitre_id}] ${n?.node?.to?.name}` : n?.node?.to?.name)))
    .join(', ');
  const usedMalwares = R.uniq((stixDomainObject.malwaresUsed?.edges ?? [])
    .map((n: { node: { to: { name: string } } }) => n?.node?.to?.name))
    .join(', ');
  const usedToolsAndChannels = R.uniq((stixDomainObject.toolsAndChannelsUsed?.edges ?? [])
    .map((n: { node: { to: { name: string } } }) => n?.node?.to?.name))
    .join(', ');

  const generatedFilters = getFilterFromEntityTypeAndNodeType(stixDomainObject.entity_type, DiamondNodeType.capabilities);

  return (
    <NodeContainer content={
      <>
        <Typography variant="h3" gutterBottom>
          {t_i18n('Last used attack patterns')}
        </Typography>
        {emptyFilled(usedAttackPatterns)}
        <Typography variant="h3" gutterBottom sx={{ marginTop: '20px' }}>
          {t_i18n('Last used malwares')}
        </Typography>
        {emptyFilled(usedMalwares)}
        <Typography variant="h3" gutterBottom sx={{ marginTop: '20px' }}>
          {t_i18n('Last used tools and channels')}
        </Typography>
        {emptyFilled(usedToolsAndChannels)}
        <Button
          component={Link}
          to={`${entityLink}/all?filters=${generatedFilters}`}
          variant="contained"
          size="small"
          sx={{
            position: 'absolute',
            left: 0,
            bottom: 0,
            width: '100%',
            height: '25px',
            color: theme.palette.primary.main,
            borderTopLeftRadius: 0,
            borderTopRightRadius: 0,
            backgroundColor:
              theme.palette.mode === 'dark'
                ? 'rgba(255, 255, 255, .1)'
                : 'rgba(0, 0, 0, .1)',
            '&:hover': {
              backgroundColor:
                theme.palette.mode === 'dark'
                  ? 'rgba(255, 255, 255, .2)'
                  : 'rgba(0, 0, 0, .2)',
            },
          }}
          className="nodrag nopan"
        >
          {t_i18n('View all')}
        </Button>
        <Handle
          style={{ visibility: 'hidden' }}
          type="target"
          position={Position.Right}
          isConnectable={false}
        />
      </>
    }
    />
  );
};

export default memo(NodeCapabilities);
