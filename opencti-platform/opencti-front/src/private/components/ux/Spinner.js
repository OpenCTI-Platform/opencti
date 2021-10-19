import React from 'react';
import Spinner from 'react-bootstrap/Spinner';

const SpinnerLoader = () => (
    <div className='d-flex justify-content-center align-items-center w-100 h-100'>
      <Spinner animation='border' variant='primary' />
    </div>
);

export default SpinnerLoader;
