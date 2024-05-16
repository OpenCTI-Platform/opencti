import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';

test('Check navigation on all pages', async ({ page }) => {
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
});
