import React from 'react';
import WidgetScatter from '../../../../components/dashboard/WidgetScatter';

const PirThreatMap = () => {
  return (
    <div>
      <div style={{ height: 500, position: 'relative' }}>
        <WidgetScatter />
      </div>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        fontSize: 12,
        transform: 'translateY(-10px)',
      }}
      >
        <span style={{ paddingLeft: 20 }}>Less recent</span>
        <span style={{ paddingRight: 10 }}>Most recent</span>
      </div>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        fontSize: 12,
        transform: 'rotate(-90deg)',
        transformOrigin: 'top left',
        width: 490,
        paddingLeft: 35,
      }}
      >
        <span>Less relevant</span>
        <span>Most relevant</span>
      </div>
    </div>
  );
};

export default PirThreatMap;
