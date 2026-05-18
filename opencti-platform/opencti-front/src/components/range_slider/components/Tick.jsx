import { getMinutes } from 'date-fns';
import PropTypes from 'prop-types';
import React from 'react';

const Tick = ({
  tick,
  count,
  format = (d) => d,
  showAllTickLabels = false,
  showUnitTickMarkers = false,
  tickLabelMultiline = false,
  tickLabelEvery = 1,
  tickIndex = 0,
}) => {
  const isFullHour = !getMinutes(tick.value);
  const showLabel = showAllTickLabels
    || (showUnitTickMarkers && tickLabelEvery > 0 && tickIndex % tickLabelEvery === 0)
    || (!showUnitTickMarkers && isFullHour);

  const tickLabelStyle = showUnitTickMarkers
    ? {
      left: `${tick.percent}%`,
      transform: 'translateX(-50%)',
      width: 'max-content',
      marginInlineStart: 0,
      whiteSpace: tickLabelMultiline ? 'normal' : 'nowrap',
      ...(tickLabelMultiline ? {
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        lineHeight: 1.15,
        gap: 1,
      } : {}),
    }
    : {
      marginInlineStart: `${-(100 / count) / 2}%`,
      width: `${100 / count}%`,
      left: `${tick.percent}%`,
    };

  return (
    <>
      <div
        className={`react_time_range__tick_marker${showLabel ? '__large' : ''}`}
        style={{ left: `${tick.percent}%` }}
      />
      {showLabel && (
        <div className="react_time_range__tick_label" style={tickLabelStyle}>
          {format(tick.value)}
        </div>
      )}
    </>
  );
};

Tick.propTypes = {
  tick: PropTypes.shape({
    id: PropTypes.string.isRequired,
    value: PropTypes.number.isRequired,
    percent: PropTypes.number.isRequired,
  }).isRequired,
  count: PropTypes.number.isRequired,
  format: PropTypes.func.isRequired,
  showAllTickLabels: PropTypes.bool,
  showUnitTickMarkers: PropTypes.bool,
  tickLabelMultiline: PropTypes.bool,
  tickLabelEvery: PropTypes.number,
  tickIndex: PropTypes.number,
};

export default Tick;
