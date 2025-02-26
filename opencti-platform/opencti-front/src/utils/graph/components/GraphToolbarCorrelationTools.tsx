import React from 'react';
import { HubOutlined, PolylineOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import GraphToolbarItem from './GraphToolbarItem';
import { useGraphContext } from '../GraphContext';
import useGraphInteractions from '../utils/useGraphInteractions';

const GraphToolbarCorrelationTools = () => {
  const { t_i18n } = useFormatter();
  const { switchCorrelationMode } = useGraphInteractions();

  const {
    graphState: {
      correlationMode,
    },
  } = useGraphContext();

  const titleCorrelationMode = () => {
    if (correlationMode === 'all') return t_i18n('Show all correlated entities');
    return t_i18n('Show only correlated observables and indicators');
  };
  const iconCorrelationMode = () => {
    if (correlationMode === 'all') return <HubOutlined />;
    return <PolylineOutlined />;
  };

  return (
    <GraphToolbarItem
      Icon={iconCorrelationMode()}
      color="primary"
      onClick={() => switchCorrelationMode()}
      title={titleCorrelationMode()}
    />
  );
};

export default GraphToolbarCorrelationTools;
