import React from 'react';
import { Dropdown as BsDropdown } from 'react-bootstrap';
import SpinnerLoader from './Spinner';

// eslint-disable-next-line react/display-name
const Dropdown = React.forwardRef((props, ref) => {
  const {
    selected, //
    placeholder,
    items,
    onSelect,
    noDataMessage,
    isLoading,
  } = props;
  if (isLoading) {
    return (
      <div className='w-25'>
        <SpinnerLoader />
      </div>
    );
  }
  return (
    <BsDropdown
      ref={ref}
      onSelect={(i) => onSelect(items.find((j) => j.id === i))}
    >
      <BsDropdown.Toggle variant='primary' id='Bdropdown-basic'>
        {selected ? selected.title : placeholder}
      </BsDropdown.Toggle>

      <BsDropdown.Menu>
        {this.props.items.length > 0 ? (
          props.items.map((range, i) => (
              <BsDropdown.Item
                key={i}
                eventKey={`${range.id}`}
                active={selected ? selected.id === range.id : false}
              >
                {range.title}
              </BsDropdown.Item>
          ))
        ) : (
          <BsDropdown.Item>{noDataMessage || 'No Data'}</BsDropdown.Item>
        )}
      </BsDropdown.Menu>
    </BsDropdown>
  );
});

Dropdown.defaultProps = {
  noDataMessage: '',
  isLoading: false,
};
export default Dropdown;
