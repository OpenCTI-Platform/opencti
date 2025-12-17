import { expect, test } from '../fixtures/baseFixtures';
import StixCoreRelationshipCreationFromEntityFormPage from '../model/form/stixCoreRelationshipCreationFromEntityForm.pageModel';
import InfrastructurePage from '../model/infrastructure.pageModel';
import InfrastructureFormPage from '../model/form/infrastructureForm.pageModel';
import InfrastructureDetailsPageModel from '../model/infrastructureDetails.pageModel';

test('Create a new relationship in infrastructure knowledge', { tag: ['@ce'] }, async ({ page }) => {
  const infrastructurePage = new InfrastructurePage(page);
  const infrastructureForm = new InfrastructureFormPage(page);
  const infrastructureDetailsPage = new InfrastructureDetailsPageModel(page);
  const stixCoreRelationshipCreationFromEntity = new StixCoreRelationshipCreationFromEntityFormPage(page);
  await page.goto('/dashboard/observations/infrastructures');
  await infrastructurePage.addNewInfrastructure();
  await infrastructureForm.fillNameInput('Test e2e');
  await infrastructurePage.getCreateInfrastructureButton().click();
  await infrastructurePage.getItemFromList('Test e2e').click();
  await expect(infrastructureDetailsPage.getInfrastructureDetailsPage()).toBeVisible();
  await infrastructureDetailsPage.getKnowledgeTab();
  await infrastructureDetailsPage.getCampaignsTab();
  await infrastructureDetailsPage.getCreateRelationshipButton().click();
  await expect(stixCoreRelationshipCreationFromEntity.getStixCoreRelationshipCreationFromEntityComponent()).toBeVisible();
});
