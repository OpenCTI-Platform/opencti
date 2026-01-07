import { expect, test } from '../fixtures/baseFixtures';
import StixCoreRelationshipCreationFromEntityFormPage from '../model/form/stixCoreRelationshipCreationFromEntityForm.pageModel';
import EventsIncidentPage from '../model/EventsIncident.pageModel';
import EventsIncidentFormPage from '../model/form/eventsIncidentForm.pageModel';
import EventsIncidentDetailsPage from '../model/EventsIncidentDetails.pageModel';

test('Create a new relationship in incident knowledge', { tag: ['@ce'] }, async ({ page }) => {
  const eventsIncidentPage = new EventsIncidentPage(page);
  const eventsIncidentForm = new EventsIncidentFormPage(page);
  const eventsIncidentDetailsPage = new EventsIncidentDetailsPage(page);
  const stixCoreRelationshipCreationFromEntity = new StixCoreRelationshipCreationFromEntityFormPage(page);
  await page.goto('/dashboard/events/incidents');
  await eventsIncidentPage.addNewIncident();
  await eventsIncidentForm.fillNameInput('Test e2e');
  await eventsIncidentPage.getCreateIncidentButton().click();
  await eventsIncidentPage.getItemFromList('Test e2e').click();
  await expect(eventsIncidentDetailsPage.getIncidentDetailsPage()).toBeVisible();
  await eventsIncidentDetailsPage.getKnowledgeTab();
  await eventsIncidentDetailsPage.getVictimologyTab();
  await eventsIncidentDetailsPage.getCreateRelationshipButton().click();
  await expect(stixCoreRelationshipCreationFromEntity.getStixCoreRelationshipCreationFromEntityComponent()).toBeVisible();
});
