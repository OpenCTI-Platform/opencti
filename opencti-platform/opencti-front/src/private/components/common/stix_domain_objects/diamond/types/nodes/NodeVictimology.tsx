import React, { memo } from 'react';
import * as R from 'ramda';
import { NodeProps, Position } from 'reactflow';
import Typography from '@mui/material/Typography';
import NodeContainer from './NodeContainer';
import { useFormatter } from '../../../../../../../components/i18n';
import { emptyFilled } from '../../../../../../../utils/String';

const NodeVictimology = ({ data }: NodeProps) => {
  const { t_i18n } = useFormatter();

  const { stixDomainObject, entityLink } = data;

  const targetedCountries = R.uniq((stixDomainObject.targetedCountries?.edges ?? [])
    .map((n: { node: { to: { name: string } } }) => n?.node?.to?.name))
    .join(', ');

  const targetedSectors = R.uniq((stixDomainObject.targetedSectors?.edges ?? [])
    .map((n: { node: { to: { name: string } } }) => n?.node?.to?.name))
    .join(', ');

  const targetedOrganizations = R.uniq((stixDomainObject.targetedOrganizations?.edges ?? [])
    .map((n: { node: { to: { name: string } } }) => n?.node?.to?.name))
    .join(', ');

  return (
    <NodeContainer link={`${entityLink}/victimology`} position={Position.Top}>
      <>
        <Typography variant="h3" gutterBottom>
          {t_i18n('Last targeted countries')}
        </Typography>
        {emptyFilled(targetedCountries)}
        <Typography variant="h3" gutterBottom sx={{ marginTop: '20px' }}>
          {t_i18n('Last targeted sectors')}
        </Typography>
        {emptyFilled(targetedSectors)}
        <Typography variant="h3" gutterBottom sx={{ marginTop: '20px' }}>
          {t_i18n('Last targeted organizations')}
        </Typography>
        {emptyFilled(targetedOrganizations)}
      </>
    </NodeContainer>
  );
};

export default memo(NodeVictimology);
