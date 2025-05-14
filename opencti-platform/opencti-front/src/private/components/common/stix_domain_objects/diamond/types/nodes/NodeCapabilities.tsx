import React, { memo } from 'react';
import * as R from 'ramda';
import { NodeProps, Position } from 'reactflow';
import Typography from '@mui/material/Typography';
import getFilterFromEntityTypeAndNodeType, { DiamondNodeType } from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';
import NodeContainer from './NodeContainer';
import { useFormatter } from '../../../../../../../components/i18n';
import { emptyFilled } from '../../../../../../../utils/String';

const NodeCapabilities = ({ data }: NodeProps) => {
  const { t_i18n } = useFormatter();

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
    <NodeContainer link={`${entityLink}/all?filters=${generatedFilters}&view=entities`} position={Position.Right}>
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
      </>
    </NodeContainer>
  );
};

export default memo(NodeCapabilities);
