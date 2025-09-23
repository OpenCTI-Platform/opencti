import { expect, test } from '../fixtures/baseFixtures';
import NotesPage from '../model/note.pageModel';
import NoteFormPage from '../model/form/noteForm.pageModel';
import NoteDetailsPage from '../model/noteDetails.pageModel';

test('Create a new note', async ({ page }) => {
  const notesPage = new NotesPage(page);
  const noteForm = new NoteFormPage(page);
  const noteDetails = new NoteDetailsPage(page);

  // go to notes
  await notesPage.goto();
  await expect(notesPage.getPage()).toBeVisible();
  // add a new note
  await notesPage.addNew();
  await noteForm.abstractField.fill('Test abstract field e2e');
  await noteForm.contentField.fill('Test Content Field Note e2e');
  await noteForm.submit();
  // open it
  await notesPage.getItemFromList('Test abstract field e2e').click();
  await expect(noteDetails.getPage()).toBeVisible();
  await expect(noteDetails.getTitle('Test abstract field e2e')).toBeVisible();
});
