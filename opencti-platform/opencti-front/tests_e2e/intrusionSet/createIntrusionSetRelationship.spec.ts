import { expect, test } from '../fixtures/baseFixtures';
import IntrusionSetPage from '../model/intrusionSet.pageModel';
import IntrusionSetFormPage from '../model/form/intrusionSetForm.pageModel';
import IntrusionSetDetailsPage from '../model/intrusionSetDetails.pageModel';
import StixCoreRelationshipCreationFromEntityFormPage from '../model/form/stixCoreRelationshipCreationFromEntityForm.pageModel';

test('Create a new relationship in intrusion set knowledge', async ({ page }) => {
  const intrusionSetPage = new IntrusionSetPage(page);
  const intrusionSetForm = new IntrusionSetFormPage(page);
  const intrusionSetDetailsPage = new IntrusionSetDetailsPage(page);
  const stixCoreRelationshipCreationFromEntity = new StixCoreRelationshipCreationFromEntityFormPage(page);
  await page.goto('/dashboard/threats/intrusion_sets');
  await intrusionSetPage.addNewIntrusionSet();
  await intrusionSetForm.fillNameInput('Test e2e');
  await intrusionSetPage.getCreateIntrusionSetButton().click();
  await intrusionSetPage.getItemFromList('Test e2e').click();
  await expect(intrusionSetDetailsPage.getIntrusionSetDetailsPage()).toBeVisible();
  await intrusionSetDetailsPage.getKnowledgeTab();
  await intrusionSetDetailsPage.getVictimologyTab();
  await intrusionSetDetailsPage.getCreateRelationshipButton().click();
  await expect(stixCoreRelationshipCreationFromEntity.getStixCoreRelationshipCreationFromEntityComponent()).toBeVisible();
});
