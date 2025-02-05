import { UIEvent } from 'react';

const stopEvent = (event: UIEvent) => {
  event.stopPropagation();
  event.preventDefault();
};

export default stopEvent;
