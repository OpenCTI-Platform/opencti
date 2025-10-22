import React, { ReactNode } from 'react';
import useComputeLink, { ComputeLinkNode } from './useComputeLink';
import useIsPublicRoute from './useIsPublicRoute';

interface ComputeLinkWrapperProps {
  children: (computeLink: (node: ComputeLinkNode) => string | undefined) => ReactNode;
}

interface WithPublicSafeComputeLinkProps {
  children: (computeLink: (node: ComputeLinkNode) => string | undefined) => ReactNode;
}

const ComputeLinkWrapper = ({ children }: ComputeLinkWrapperProps) => {
  const computeLink = useComputeLink();
  return <>{children(computeLink)}</>;
};

/**
 * Component that safely provides the computeLink function.
 * In public routes, provides a no-op function.
 * In private routes, provides the actual computeLink function.
 *
 * @example
 * ```tsx
 * <WithPublicSafeComputeLink>
 *   {(computeLink) => (
 *     <YourComponent computeLink={computeLink} {...props} />
 *   )}
 * </WithPublicSafeComputeLink>
 * ```
 */
const WithPublicSafeComputeLink = ({ children }: WithPublicSafeComputeLinkProps) => {
  const isPublicRoute = useIsPublicRoute();

  if (isPublicRoute) {
    // Public route: provide no-op function
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return <>{children((..._args: any) => '')}</>;
  }

  // Private route: use wrapper that can call the hook
  return <ComputeLinkWrapper>{children}</ComputeLinkWrapper>;
};

WithPublicSafeComputeLink.displayName = 'WithPublicSafeComputeLink';

export default WithPublicSafeComputeLink;
