import PropTypes from 'prop-types';
import React from 'react';

const getTrackConfig = ({ error, source, target, disabled }) => {
  const basicStyle = {
    left: `${source.percent}%`,
    width: `calc(${target.percent - source.percent}% - 1px)`,
  };

  if (disabled) return basicStyle;

  const coloredTrackStyle = error
    ? {
      backgroundColor: 'rgba(214,0,11,0.5)',
      borderLeft: '1px solid rgba(214,0,11,0.5)',
      borderRight: '1px solid rgba(214,0,11,0.5)',
    }
    : {
      backgroundColor: 'rgba(98, 203, 102, 0.5)',
      borderLeft: '1px solid #62CB66',
      borderRight: '1px solid #62CB66',
    };

  return { ...basicStyle, ...coloredTrackStyle };
};

const Track = ({ error, source, target, getTrackProps, disabled }) => (
  <div
    className={`react_time_range__track${disabled ? '__disabled' : ''}`}
    style={getTrackConfig({ error, source, target, disabled })}
    {...getTrackProps()}
  />
);

Track.propTypes = {
  source: PropTypes.shape({
    id: PropTypes.string.isRequired,
    value: PropTypes.number.isRequired,
    percent: PropTypes.number.isRequired,
  }).isRequired,
  target: PropTypes.shape({
    id: PropTypes.string.isRequired,
    value: PropTypes.number.isRequired,
    percent: PropTypes.number.isRequired,
  }).isRequired,
  getTrackProps: PropTypes.func.isRequired,
  disabled: PropTypes.bool,
};

Track.defaultProps = { disabled: false };

export default Track;
