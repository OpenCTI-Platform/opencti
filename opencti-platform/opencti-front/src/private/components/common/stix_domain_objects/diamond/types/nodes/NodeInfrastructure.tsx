import React, { memo } from 'react';
import * as R from 'ramda';
import { Handle, NodeProps, Position } from 'reactflow';
import { useTheme } from '@mui/styles';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import { Link } from 'react-router-dom';
import getFilterFromEntityTypeAndNodeType, { DiamondNodeType } from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';
import type { Theme } from '../../../../../../../components/Theme';
import { useFormatter } from '../../../../../../../components/i18n';
import { emptyFilled } from '../../../../../../../utils/String';

const getStyles = (theme: Theme) => ({
  node: {
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
  },
  nodeContent: {
    width: '100%',
    height: '100%',
    overflowY: 'auto',
    padding: '20px',
  },
  handle: {
    visibility: 'hidden',
  },
  label: {
    marginTop: '20px',
  },
  buttonExpand: {
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
  },
});

const NodeInfrastructure = ({ data }: NodeProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const styles = getStyles(theme);

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

  console.log('stixDomainObject : ', stixDomainObject);
  const generatedFilter = getFilterFromEntityTypeAndNodeType(stixDomainObject.entity_type, DiamondNodeType.infrastructure);

  const encoded = encodeURIComponent(generatedFilter);

  return (
    <div style={styles.node}>
      <div style={styles.nodeContent}>
        <Typography variant="h3" gutterBottom>
          {t_i18n('Last used IP addresses')}
        </Typography>
        {emptyFilled(usedIPs)}
        <Typography variant="h3" gutterBottom sx={styles.label}>
          {t_i18n('Last used domains')}
        </Typography>
        {emptyFilled(usedDomains)}
        <Typography variant="h3" gutterBottom sx={styles.label}>
          {t_i18n('Last used infrastructures')}
        </Typography>
        {emptyFilled(usedInfrastructures)}
      </div>
      <Button
        component={Link}
        to={`${entityLink}/all`}
        // to={`${entityLink}/all?filters=${encoded}`}
        variant="contained"
        size="small"
        sx={styles.buttonExpand}
        className="nodrag nopan"
      >
        {t_i18n('View all')}
      </Button>
      <Handle
        sx={styles.handle}
        type="target"
        position={Position.Left}
        isConnectable={false}
      />
    </div>
  );
};

export default memo(NodeInfrastructure);
