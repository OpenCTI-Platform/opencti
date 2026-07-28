import useGranted, { EXPLORE_EXUPDATE } from './useGranted';

interface DashboardPermissions {
  /** User has at least the EXPLORE base capability */
  canView: boolean;
  /** User has AM edit|admin role — may switch variable values at runtime */
  canSwitchValues: boolean;
  /** User has AM edit|admin role AND EXPLORE_EXUPDATE capability — may modify structure */
  canEditStructure: boolean;
}

/**
 * Returns the effective dashboard permissions for the current user based on
 * their Authorized-Member (AM) role on the workspace and their platform capabilities.
 *
 * @param currentUserAccessRight - value of `Workspace.currentUserAccessRight` (view | edit | admin | null)
 */
const useDashboardPermissions = (
  currentUserAccessRight: string | null | undefined,
): DashboardPermissions => {
  const hasEditRole = currentUserAccessRight === 'edit' || currentUserAccessRight === 'admin';
  const hasUpdateCapa = useGranted([EXPLORE_EXUPDATE]);

  return {
    canView: !!currentUserAccessRight,
    canSwitchValues: hasEditRole,
    canEditStructure: hasEditRole && hasUpdateCapa,
  };
};

export default useDashboardPermissions;
