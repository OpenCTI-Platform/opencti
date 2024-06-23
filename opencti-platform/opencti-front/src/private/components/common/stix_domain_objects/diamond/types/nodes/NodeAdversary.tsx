import React, { memo } from 'react';
import { Handle, NodeProps, Position } from 'reactflow';
import { makeStyles } from '@mui/styles';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import { Link } from 'react-router-dom';
import type { Theme } from '../../../../../../../components/Theme';
import { useFormatter } from '../../../../../../../components/i18n';
import { emptyFilled } from '../../../../../../../utils/String';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  node: {
    position: 'relative',
    border:
        theme.palette.mode === 'dark'
          ? '1px solid rgba(255, 255, 255, 0.12)'
          : '1px solid rgba(0, 0, 0, 0.12)',
    borderRadius: 4,
    backgroundColor: theme.palette.background.paper,
    width: 400,
    height: 200,
    paddingBottom: 25,
  },
  nodeContent: {
    width: '100%',
    height: '100%',
    overflowY: 'auto',
    padding: 20,
  },
  handle: {
    visibility: 'hidden',
  },
  label: {
    marginTop: 20,
  },
  buttonExpand: {
    position: 'absolute',
    left: 0,
    bottom: 0,
    width: '100%',
    height: 25,
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
}));

const NodeAdversary = ({ data }: NodeProps) => {
  const classes = useStyles();
  const { stixDomainObject, entityLink } = data;
  const isArsenal = ['Malware', 'Tool', 'Channel'].includes(stixDomainObject.entity_type);
  const aliases = stixDomainObject.aliases?.slice(0, 5).join(', ');
  const attributedTo = (stixDomainObject.attributedTo?.edges ?? [])
    .map((n: { node: { to: { name: string } } }) => n?.node?.to?.name)
    .join(', ');
  const usedBy = (stixDomainObject.usedBy?.edges ?? [])
    .map((n: { node: { from: { name: string } } }) => n?.node?.from?.name)
    .join(', ');
  const { t_i18n } = useFormatter();
  return (
    <div className={classes.node} >
      <div className={classes.nodeContent}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Aliases')}
        </Typography>
        {emptyFilled(aliases)}
        <Typography variant="h3" gutterBottom={true} className={classes.label}>
          {isArsenal ? t_i18n('Last used by') : t_i18n('Last attributions')}
        </Typography>
        {isArsenal ? emptyFilled(usedBy) : emptyFilled(attributedTo)}
      </div>
      <Button
        component={Link}
        to={isArsenal ? `${entityLink}/threats` : `${entityLink}/attribution`}
        variant="contained"
        size="small"
        classes={{ root: classes.buttonExpand }}
        className="nodrag nopan"
      >
        {t_i18n('View all')}
      </Button>
      <Handle
        className={classes.handle}
        type="target"
        position={Position.Bottom}
        isConnectable={false}
      />
    </div>
  );
};

export default memo(NodeAdversary);
