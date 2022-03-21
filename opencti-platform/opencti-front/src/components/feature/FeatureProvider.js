import React, { createContext } from 'react';

export const FeatureContext = createContext({});
/**
 * Component exposing the capability to conditionally render components depending
 * on if they have been flagged to be disabled.
 * This should wrap the entire application or at least the most root component where
 * feature flagging is needed.
 * (Whole app is best)
 *
 * Components that should be flagged for disabling need to be wrapped in a FeatureFlag component.
 *
 * Disable flagging of a feature is done with environment variables prefixed with REACT_APP_FEAT
 * and disabled with 0.
 *
 * Example:
 *
 * REACT_APP_FEAT_VSAC = 0.
 *
 * with a <FeatureFlag tag="VSAC">...</FeatureFlag>
 *
 * Children of the flag will not render.
 *
 * @returns {JSX.Element}
 */
const FeatureProvider = (props) => {
  const { children } = props;

  const envFeatMap = [];
  Object.keys(process.env)
    .filter((k) => k.startsWith('REACT_APP_FEAT_'))
    .map((k) => envFeatMap.push({ env: k, feature: k.replace('REACT_APP_FEAT_', '') }));

  const disableMap = {};
  envFeatMap.forEach((m) => {
    const varValue = process.env[m.env];
    disableMap[m.feature] = varValue === '0';
  });

  return (
    <FeatureContext.Provider value={disableMap}>
      {children}
    </FeatureContext.Provider>
  );
};

export default FeatureProvider;
