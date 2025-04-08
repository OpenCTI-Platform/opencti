import React from 'react';
import { HubOutlined, PolylineOutlined } from '@mui/icons-material';
import { useFormatter } from '../../i18n';
import GraphToolbarItem from './GraphToolbarItem';
import { useGraphContext } from '../GraphContext';
import useGraphInteractions from '../utils/useGraphInteractions';

const GraphToolbarCorrelationTools = () => {
  const { t_i18n } = useFormatter();
  const { setCorrelationMode } = useGraphInteractions();

  const {
    graphState: {
      correlationMode,
    },
  } = useGraphContext();

  return (
    <>
      <GraphToolbarItem
        Icon={<HubOutlined />}
        color={correlationMode === 'all' ? 'secondary' : 'primary'}
        onClick={() => setCorrelationMode('all')}
        title={t_i18n('Show all correlated entities')}
      />
      <GraphToolbarItem
        Icon={<PolylineOutlined />}
        color={correlationMode === 'observables' ? 'secondary' : 'primary'}
        onClick={() => setCorrelationMode('observables')}
        title={t_i18n('Show only correlated observables and indicators')}
      />
    </>
  );
};

export default GraphToolbarCorrelationTools;
