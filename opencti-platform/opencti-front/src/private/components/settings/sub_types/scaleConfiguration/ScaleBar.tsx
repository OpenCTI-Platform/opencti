import makeStyles from '@mui/styles/makeStyles';
import React from 'react';
import { Theme } from '../../../../../components/Theme';
import { ScaleConfig } from './scale';

const useStyles = makeStyles<Theme>(() => ({
  scaleBar: {
    display: 'flex',
    width: '100%',
    padding: '20px 0 20px 0',
  },
}));

const ScaleBar = ({ scale }: { scale: ScaleConfig }) => {
  const classes = useStyles();

  const ticks = [scale.min, ...scale.ticks];

  const getTickRange = (tickIndex: number) => {
    if (tickIndex < 0 || ticks.length <= tickIndex) {
      return 0;
    }
    const tick = ticks.at(tickIndex);
    const nextTick = tickIndex < ticks.length - 1 ? ticks.at(tickIndex + 1) : scale.max;
    const tickValue = Number.parseInt((tick?.value ?? 0).toString(), 10);
    const nextTickValue = Number.parseInt((nextTick?.value ?? 0).toString(), 10);
    return nextTickValue - tickValue;
  };

  return (
    <div className={classes.scaleBar}>
      {ticks.map((tick, index) => (
        <div
          key={index}
          style={{
            display: 'flex',
            flexDirection: 'column',
            flexGrow: `${getTickRange(index) / (scale.max.value - scale.min.value)}`,
          }}
        >
          <div className="rail">
              <span
                className="railSpan"
                style={{
                  backgroundColor: `${tick.color ? tick.color : '#00b1ff'}`,
                  height: '5px',
                  width: '100%',
                  display: 'block',
                }}
              ></span>
          </div>
          <div style={{ display: 'flex', padding: '10px 0' }}>
              <span style={{ color: `${index === 0 ? '#607d8b' : tick.color}` }}>
                {tick.value}
              </span>
            <div style={{ flex: 1, textAlign: 'center' }}>{tick.label}</div>
            {
              index === scale.ticks.length
                ? (<span style={{ color: `${tick.color}` }}>{scale.max.value}</span>)
                : (<></>)
            }
          </div>
        </div>
      ))}
    </div>
  );
};

export default ScaleBar;
