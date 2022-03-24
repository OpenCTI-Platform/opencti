import React, { useContext } from 'react';
import PropTypes from 'prop-types';
import { FeatureContext } from './FeatureProvider';

/**
 * Should wrap components that can be disabled with a feature flag.
 *
 * Usage:
 *
 * <FeatureFlag tag="VSAC"> ... </FeatureFlag>
 *
 * @returns {*|JSX.Element}
 */
const FeatureFlag = (props) => {
  const featureContext = useContext(FeatureContext);
  const { children, tag, alt } = props;
  const disabled = featureContext[tag] ?? false;
  return (disabled ? alt : children) ?? <></>;
};

FeatureFlag.propTypes = {
  children: PropTypes.oneOfType([
    PropTypes.arrayOf(PropTypes.node),
    PropTypes.node,
  ]).isRequired,
  alt: PropTypes.node,
  tag: PropTypes.string.isRequired,
};

export default FeatureFlag;
