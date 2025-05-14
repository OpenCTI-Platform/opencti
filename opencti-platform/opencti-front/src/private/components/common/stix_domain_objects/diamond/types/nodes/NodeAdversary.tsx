import React, { memo } from 'react';
import * as R from 'ramda';
import { NodeProps, Position } from 'reactflow';
import Typography from '@mui/material/Typography';
import getFilterFromEntityTypeAndNodeType, { DiamondNodeType } from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';
import NodeContainer from '@components/common/stix_domain_objects/diamond/types/nodes/NodeContainer';
import { useFormatter } from '../../../../../../../components/i18n';
import { emptyFilled } from '../../../../../../../utils/String';

const NodeAdversary = ({ data }: NodeProps) => {
  const { t_i18n } = useFormatter();

  const { stixDomainObject, entityLink } = data;

  const isArsenal = ['Malware', 'Tool', 'Channel'].includes(stixDomainObject.entity_type);

  const aliases = stixDomainObject.aliases?.slice(0, 5).join(', ');

  const attributedTo = R.uniq((stixDomainObject.attributedTo?.edges ?? [])
    .map((n: { node: { to: { name: string } } }) => n?.node?.to?.name))
    .join(', ');

  const usedBy = R.uniq((stixDomainObject.usedBy?.edges ?? [])
    .map((n: { node: { from: { name: string } } }) => n?.node?.from?.name))
    .join(', ');

  const generatedFilters = getFilterFromEntityTypeAndNodeType(stixDomainObject.entity_type, DiamondNodeType.adversary);

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
        {isArsenal ? emptyFilled(usedBy) : emptyFilled(attributedTo)}
      </>
    </NodeContainer>
  );
};

export default memo(NodeAdversary);
