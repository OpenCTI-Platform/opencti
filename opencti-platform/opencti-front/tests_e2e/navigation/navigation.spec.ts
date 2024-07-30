import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import ReportPage from '../model/report.pageModel';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import StixDomainObjectContentTabPage from '../model/StixDomainObjectContentTab.pageModel';
import ContainerObservablesPage from '../model/containerObservables.pageModel';
import StixCoreObjectDataTab from '../model/StixCoreObjectDataTab.pageModel';

/**
 * Goal: validate that everything is opening wihtout errors
 * Content of the test
 * -------------------
 * Go on report
 * view list of report
 * open one report in overview
 * navigate to knowledge
 * navigate to content
 * navigate to entities
 * navigate to observables
 * navigate to data
 * @param page
 */
const navigateReports = async (page: Page) => {
  const reportNameFromInitData = 'E2E dashboard - Report - now';

  const reportPage = new ReportPage(page);
  await reportPage.goto();
  await expect(reportPage.getPage()).toBeVisible();
  await expect(page.getByText(reportNameFromInitData)).toBeVisible();
  await reportPage.getItemFromList(reportNameFromInitData).click();

  const reportDetailsPage = new ReportDetailsPage(page);
  await expect(reportDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await reportDetailsPage.goToKnowledgeTab();
  await expect(page.getByTestId('report-knowledge')).toBeVisible();
  await page.getByLabel('TimeLine view').click();
  await page.getByLabel('Correlation view').click();
  await page.getByLabel('Tactics matrix view').click();
  await page.getByLabel('Graph view').click();

  // -- Content
  await reportDetailsPage.goToContentTab();
  const contentTab = new StixDomainObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();
  await contentTab.getContentMappingViewButton().click();
  await expect(page.getByRole('button', { name: 'Clear mappings' })).toBeVisible();
  await contentTab.getContentViewButton().click();
  await expect(page.getByText('Description', { exact: true })).toBeVisible();
  await expect(page.getByText('Mappable content')).toBeVisible();

  // -- Entities
  await reportDetailsPage.goToEntitiesTab();
  await expect(page.getByText('Entity types')).toBeVisible();
  await expect(page.getByText('Add entity')).toBeVisible();

  // -- Artifact / Observables
  await reportDetailsPage.goToObservablesTab();
  const observablesTab = new ContainerObservablesPage(page);
  await expect(observablesTab.getPage()).toBeVisible();

  // -- Data
  await reportDetailsPage.goToDataTab();
  const dataTab = new StixCoreObjectDataTab(page);
  await expect(dataTab.getPage()).toBeVisible();
};

const navigateAllMenu = async (page: Page) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();

  // Checking Analyses menu
  await leftBarPage.clickOnMenu('Analyses');
  await leftBarPage.expectPage('Analyses', 'Reports');
  await leftBarPage.expectPage('Analyses', 'Groupings');
  await leftBarPage.expectPage('Analyses', 'Malware analyses');
  await leftBarPage.expectPage('Analyses', 'Notes');
  await leftBarPage.expectPage('Analyses', 'External references');

  // Checking Cases menu
  await leftBarPage.clickOnMenu('Cases');
  await leftBarPage.expectPage('Cases', 'Incident responses');
  await leftBarPage.expectPage('Cases', 'Requests for information');
  await leftBarPage.expectPage('Cases', 'Requests for takedown');
  await leftBarPage.expectPage('Cases', 'Tasks');
  await leftBarPage.expectPage('Cases', 'Requests for takedown');

  // Checking Events menu
  await leftBarPage.clickOnMenu('Events');
  await leftBarPage.expectPage('Events', 'Incidents');
  await leftBarPage.expectPage('Events', 'Sightings');
  await leftBarPage.expectPage('Events', 'Observed data');

  // Checking Observations menu
  await leftBarPage.clickOnMenu('Observations');
  await leftBarPage.expectPage('Observations', 'Observables');
  await leftBarPage.expectPage('Observations', 'Artifacts');
  await leftBarPage.expectPage('Observations', 'Indicators');
  await leftBarPage.expectPage('Observations', 'Infrastructures');

  // Checking Threats menu
  await leftBarPage.clickOnMenu('Threats');
  await leftBarPage.expectPage('Threats', 'Threat actors (group)');
  await leftBarPage.expectPage('Threats', 'Threat actors (individual)');
  await leftBarPage.expectPage('Threats', 'Intrusion sets');
  await leftBarPage.expectPage('Threats', 'Campaigns');

  // Checking Arsenal menu
  await leftBarPage.clickOnMenu('Arsenal');
  await leftBarPage.expectPage('Arsenal', 'Malware');
  await leftBarPage.expectPage('Arsenal', 'Channels');
  await leftBarPage.expectPage('Arsenal', 'Tools');
  await leftBarPage.expectPage('Arsenal', 'Vulnerabilities');

  // Checking Techniques menu
  await leftBarPage.clickOnMenu('Techniques');
  await leftBarPage.expectPage('Techniques', 'Attack patterns');
  await leftBarPage.expectPage('Techniques', 'Narratives');
  await leftBarPage.expectPage('Techniques', 'Courses of action');
  await leftBarPage.expectPage('Techniques', 'Data components');
  await leftBarPage.expectPage('Techniques', 'Data sources');

  // Checking Entities menu
  await leftBarPage.clickOnMenu('Entities');
  await leftBarPage.expectPage('Entities', 'Sectors');
  // await leftBarPage.expectPage('Entities', 'Events'); <-- COMPLEX FOR NOW BECAUSE WE HAVE TWO MENUS WITH THE SAME NAME
  await leftBarPage.expectPage('Entities', 'Organizations');
  await leftBarPage.expectPage('Entities', 'Systems');
  await leftBarPage.expectPage('Entities', 'Individuals');

  // Checking Locations menu
  await leftBarPage.clickOnMenu('Locations');
  await leftBarPage.expectPage('Locations', 'Regions');
  await leftBarPage.expectPage('Locations', 'Countries');
  await leftBarPage.expectPage('Locations', 'Administrative areas');
  await leftBarPage.expectPage('Locations', 'Cities');
  await leftBarPage.expectPage('Locations', 'Positions');

  // Checking Data menu
  // TODO SUB MENUS
  await leftBarPage.clickOnMenu('Data');
  // await leftBarPage.expectPage('Data', 'Entities'); <-- COMPLEX FOR NOW BECAUSE WE HAVE TWO MENUS WITH THE SAME NAME
  await leftBarPage.expectPage('Data', 'Relationships');

  // Checking Settings menu
  // TODO SUB MENUS
  await leftBarPage.clickOnMenu('Settings');
  await leftBarPage.expectPage('Settings', 'Parameters');
  await leftBarPage.expectPage('Settings', 'File indexing');

  // Other
  await leftBarPage.clickOnMenu('Investigations');
  await expect(page.getByRole('paragraph')).toHaveText('Investigations');
  await leftBarPage.clickOnMenu('Dashboards');
  await expect(page.getByRole('paragraph')).toHaveText('Dashboards');
};

test('Check navigation on all pages', { tag: ['@navigation'] }, async ({ page }) => {
  await navigateAllMenu(page);
  await navigateReports(page);
});
