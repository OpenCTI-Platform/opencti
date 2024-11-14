import React from 'react';
import PropTypes from 'prop-types';

export const SliderRail = ({ getRailProps }) => (
  <>
    <div className='react_time_range__rail__outer' {...getRailProps()} />
    <div className='react_time_range__rail__inner' />
  </>
);

SliderRail.propTypes = { getRailProps: PropTypes.func.isRequired };

export default SliderRail;
