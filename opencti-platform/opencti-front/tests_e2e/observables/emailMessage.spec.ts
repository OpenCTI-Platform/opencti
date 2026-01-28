import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import ObservableFormPage from '../model/form/observableForm.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import ObservablesPage from '../model/observable.pageModel';
import ObservableDetailsPage from '../model/observableDetails.pageModel';

/**
 * Content of the test
 * -------------------
 * Create an email message.
 */
test('Email message CRUD', { tag: ['@ce'] }, async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);
  const observablePage = new ObservablesPage(page);
  const observableForm = new ObservableFormPage(page);
  const observableDetailsPage = new ObservableDetailsPage(page);

  await observablePage.goto();
  await leftBarPage.open();
  await leftBarPage.clickOnMenu('Observations', 'Observables');

  const emailMessage = {
    subject: `My super email - ${uuid()}`,
    body: `This is a super email you must read - ${uuid()}`,
  };

  await observablePage.addNew();
  await observableForm.chooseType('Email message');
  await observableForm.emailMessageBodyField.fill(emailMessage.body);
  await observableForm.emailMessageSubjectField.fill(emailMessage.subject);
  await observableForm.submit();
  await observablePage.getItemFromList(emailMessage.body).click();
  await expect(observableDetailsPage.getPage()).toBeVisible();
});
