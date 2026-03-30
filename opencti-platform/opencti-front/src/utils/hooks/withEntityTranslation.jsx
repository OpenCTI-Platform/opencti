import React from 'react';
import useEntityTranslation from './useEntityTranslation';

const withEntityTranslation = (WrappedComponent) => {
  const WithEntityTranslationWrapper = (props) => {
    const { translateEntityType } = useEntityTranslation();
    return (
      <WrappedComponent
        {...props}
        translateEntityType={translateEntityType}
      />
    );
  };
  WithEntityTranslationWrapper.displayName = `withEntityTranslation(${WrappedComponent.displayName || WrappedComponent.name || 'Component'})`;
  return WithEntityTranslationWrapper;
};

export default withEntityTranslation;
