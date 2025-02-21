import React, { memo } from 'react';
import * as R from 'ramda';
import { Handle, NodeProps, Position } from 'reactflow';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import { Link } from 'react-router-dom';
import getFilterFromEntityTypeAndNodeType, { DiamondNodeType } from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../../components/Theme';
import { useFormatter } from '../../../../../../../components/i18n';
import { emptyFilled } from '../../../../../../../utils/String';

const NodeAdversary = ({ data }: NodeProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

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
    <div style={{
      position: 'relative',
      border:
        theme.palette.mode === 'dark'
          ? '1px solid rgba(255, 255, 255, 0.12)'
          : '1px solid rgba(0, 0, 0, 0.12)',
      borderRadius: 4,
      backgroundColor: theme.palette.background.paper,
      width: '400px',
      height: '200px',
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
          {t_i18n('Aliases')}
        </Typography>
        {emptyFilled(aliases)}
        <Typography variant="h3" gutterBottom sx={{ marginTop: '20px' }}>
          {isArsenal ? t_i18n('Last used by') : t_i18n('Last attributions')}
        </Typography>
        {isArsenal ? emptyFilled(usedBy) : emptyFilled(attributedTo)}
      </div>
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
        position={Position.Bottom}
        isConnectable={false}
      />
    </div>
  );
};

export default memo(NodeAdversary);
