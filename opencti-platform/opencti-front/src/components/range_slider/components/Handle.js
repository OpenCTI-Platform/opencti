import PropTypes from 'prop-types';
import React from 'react';

const Handle = ({
  error,
  domain: [min, max],
  handle: { id, value, percent = 0 },
  disabled,
  getHandleProps,
}) => {
  const leftPosition = `${percent}%`;

  return (
    <>
      <div className='react_time_range__handle_wrapper' style={{ left: leftPosition }} {...getHandleProps(id)} />
      <div
        role='slider'
        aria-valuemin={min}
        aria-valuemax={max}
        aria-valuenow={value}
        className={`react_time_range__handle_container${disabled ? '__disabled' : ''}`}
        style={{ left: leftPosition }}
      >
        <div className={`react_time_range__handle_marker${error ? '__error' : ''}`} />
      </div>
    </>
  );
};

Handle.propTypes = {
  domain: PropTypes.array.isRequired,
  handle: PropTypes.shape({
    id: PropTypes.string.isRequired,
    value: PropTypes.number.isRequired,
    percent: PropTypes.number.isRequired,
  }).isRequired,
  getHandleProps: PropTypes.func.isRequired,
  disabled: PropTypes.bool,
  style: PropTypes.object,
};

Handle.defaultProps = { disabled: false };

export default Handle;
