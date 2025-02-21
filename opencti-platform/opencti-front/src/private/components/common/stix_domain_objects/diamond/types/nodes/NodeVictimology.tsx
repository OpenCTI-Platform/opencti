import React, { memo } from 'react';
import * as R from 'ramda';
import { Handle, NodeProps, Position } from 'reactflow';
import { useTheme } from '@mui/styles';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import { Link } from 'react-router-dom';
import type { Theme } from '../../../../../../../components/Theme';
import { useFormatter } from '../../../../../../../components/i18n';
import { emptyFilled } from '../../../../../../../utils/String';

const NodeVictimology = ({ data }: NodeProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

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
    <div style={{
      position: 'relative',
      border:
        theme.palette.mode === 'dark'
          ? '1px solid rgba(255, 255, 255, 0.12)'
          : '1px solid rgba(0, 0, 0, 0.12)',
      borderRadius: '4px',
      backgroundColor: theme.palette.background.paper,
      width: '400px',
      height: '300px',
      paddingBottom: '25px',
    }}
    >
      <div style={{
        width: '100%',
        height: '100%',
        overflowY: 'auto',
        padding: '20px',
      }}
      >
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
      </div>
      <Button
        component={Link}
        to={`${entityLink}/victimology`}
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
        position={Position.Top}
        isConnectable={false}
      />
    </div>
  );
};

export default memo(NodeVictimology);
