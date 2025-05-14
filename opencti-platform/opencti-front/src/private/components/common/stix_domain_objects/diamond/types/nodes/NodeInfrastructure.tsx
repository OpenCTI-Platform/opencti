import React, { memo } from 'react';
import * as R from 'ramda';
import { NodeProps, Position } from 'reactflow';
import Typography from '@mui/material/Typography';
import getFilterFromEntityTypeAndNodeType, { DiamondNodeType } from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';
import NodeContainer from '@components/common/stix_domain_objects/diamond/types/nodes/NodeContainer';
import { useFormatter } from '../../../../../../../components/i18n';
import { emptyFilled } from '../../../../../../../utils/String';

const NodeInfrastructure = ({ data }: NodeProps) => {
  const { t_i18n } = useFormatter();

  const { stixDomainObject, entityLink } = data;

  const usedIPs = R.uniq((stixDomainObject.relatedIPs?.edges ?? [])
    .map((n: { node: { from: { representative: { main: string } } } }) => n?.node?.from?.representative?.main))
    .join(', ');

  const usedDomains = R.uniq((stixDomainObject.relatedDomains?.edges ?? [])
    .map((n: { node: { from: { representative: { main: string } } } }) => n?.node?.from?.representative?.main))
    .join(', ');

  const usedInfrastructures = R.uniq((stixDomainObject.infrastructuresUsed?.edges ?? [])
    .map((n: { node: { to: { name: string } } }) => n?.node?.to?.name))
    .join(', ');

  const generatedFilters = getFilterFromEntityTypeAndNodeType(stixDomainObject.entity_type, DiamondNodeType.infrastructure);

  return (
    <NodeContainer link={`${entityLink}/all?filters=${generatedFilters}&view=entities`} position={Position.Left}>
      <>
        <Typography variant="h3" gutterBottom>
          {t_i18n('Last used IP addresses')}
        </Typography>
        {emptyFilled(usedIPs)}
        <Typography variant="h3" gutterBottom sx={{
          marginTop: '20px',
        }}
        >
          {t_i18n('Last used domains')}
        </Typography>
        {emptyFilled(usedDomains)}
        <Typography variant="h3" gutterBottom sx={{
          marginTop: '20px',
        }}
        >
          {t_i18n('Last used infrastructures')}
        </Typography>
        {emptyFilled(usedInfrastructures)}
      </>
    </NodeContainer>
  );
};

export default memo(NodeInfrastructure);
