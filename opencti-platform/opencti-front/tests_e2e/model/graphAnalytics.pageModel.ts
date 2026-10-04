import { Page } from '@playwright/test';

export default class GraphAnalyticsPage {
  constructor(private page: Page) {}

  // region Similar tab
  gotoSimilarTab(intrusionSetId: string) {
    return this.page.goto(`/dashboard/threats/intrusion_sets/${intrusionSetId}/similar`);
  }

  getSimilarTab() {
    return this.page.getByTestId('graph-similar-tab');
  }

  getSimilarItem(name: string) {
    return this.page.getByTestId('graph-similar-item').filter({ hasText: name });
  }

  getCompareButton() {
    return this.page.getByRole('button', { name: 'Compare side by side' }).first();
  }

  getCompareColumns() {
    return this.page.getByTestId('graph-compare-column');
  }
  // endregion

  // region Connect to / path finder
  async openConnectTo() {
    await this.page.getByRole('button', { name: 'Popover of actions' }).click();
    await this.page.getByRole('menuitem', { name: 'Connect to...' }).click();
  }

  getPathFinder() {
    return this.page.getByTestId('graph-path-finder');
  }

  getTargetEntityInput() {
    return this.page.getByRole('combobox', { name: 'Target entity' });
  }

  getFindPathsButton() {
    return this.page.getByRole('button', { name: 'Find paths' });
  }

  getPathChains() {
    return this.page.getByTestId('graph-path-chain');
  }

  getStartInvestigationButton() {
    return this.page.getByRole('button', { name: 'Start an investigation with the selected paths' });
  }
  // endregion

  // region investigation canvas
  getCanvasSearchInput() {
    return this.page.getByPlaceholder('Search these results...');
  }

  getFindPathToolbarButton() {
    return this.page.getByRole('button', { name: 'Find path between the two selected entities' });
  }

  getExpandBySimilarityToolbarButton() {
    return this.page.getByRole('button', { name: 'Expand by similarity' });
  }

  getAddPathsToGraphButton() {
    return this.page.getByRole('button', { name: 'Add the selected paths to the graph' });
  }

  getExpandBySimilarityDialog() {
    return this.page.getByTestId('graph-expand-similarity');
  }
  // endregion

  // region clusters
  gotoClusters() {
    return this.page.goto('/dashboard/analyses/clusters');
  }

  gotoCluster(clusterId: string) {
    return this.page.goto(`/dashboard/analyses/clusters/${clusterId}`);
  }

  getClustersPage() {
    return this.page.getByTestId('graph-clusters-page');
  }

  getAnalyticsStatus() {
    return this.page.getByTestId('graph-analytics-status');
  }

  getClusterPage() {
    return this.page.getByTestId('graph-cluster-page');
  }

  getClusterMembers() {
    return this.page.getByTestId('graph-cluster-members');
  }

  getCreateGroupingButton() {
    return this.page.getByTestId('graph-cluster-create-grouping');
  }

  getPromoteSubmitButton() {
    return this.page.getByTestId('graph-cluster-promote-submit');
  }
  // endregion

  // region Dashboards
  gotoDashboards() {
    return this.page.goto('/dashboard/workspaces/dashboards');
  }

  getCreateDashboardFromTemplateButton() {
    return this.page.getByTestId('CreateDashboardFromTemplate');
  }

  getDashboardTemplate(templateId: string) {
    return this.page.getByTestId(`dashboard-template-${templateId}`);
  }
  // endregion
}
