import { $$asyncIterator } from 'iterall';

const withCancel = (asyncIterator, onCancel) => {
  const updatedAsyncIterator = {
    return() {
      onCancel();
      return asyncIterator.return();
    },
    next() {
      return asyncIterator.next();
    },
    throw(error) {
      return asyncIterator.throw(error);
    },
  };
  return { [$$asyncIterator]: () => updatedAsyncIterator };
};

export default withCancel;
