import PropTypes from 'prop-types';
import React from 'react';

const KeyboardHandle = ({ domain: [min, max], handle: { id, value, percent = 0 }, disabled, getHandleProps }) => (
  <button
    role='slider'
    aria-valuemin={min}
    aria-valuemax={max}
    aria-valuenow={value}
    className='react_time_range__keyboard_handle'
    style={{
      left: `${percent}%`,
      backgroundColor: disabled ? '#666' : '#ffc400',
    }}
    {...getHandleProps(id)}
  />
);

KeyboardHandle.propTypes = {
  domain: PropTypes.array.isRequired,
  handle: PropTypes.shape({
    id: PropTypes.string.isRequired,
    value: PropTypes.number.isRequired,
    percent: PropTypes.number.isRequired,
  }).isRequired,
  getHandleProps: PropTypes.func.isRequired,
  disabled: PropTypes.bool,
};

KeyboardHandle.defaultProps = { disabled: false };

export default KeyboardHandle;
