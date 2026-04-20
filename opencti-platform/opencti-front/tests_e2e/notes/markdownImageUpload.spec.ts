/**
 * E2E tests for Markdown image upload feature.
 *
 * Slice coverage:
 *  - Slice 1: Insert image via button, local blob preview renders in Preview tab
 *  - Slice 2: Submit persists image to storage, re-read renders from backend URL
 */

import path from 'path';
import { expect, test } from '../fixtures/baseFixtures';
import NotesPage from '../model/note.pageModel';
import NoteFormPage from '../model/form/noteForm.pageModel';
import NoteDetailsPage from '../model/noteDetails.pageModel';
import MarkdownImageFieldPageModel from '../model/field/MarkdownImageField.pageModel';

const TEST_IMAGE_PATH = path.join(__dirname, 'assets', 'test-image.png');

test.describe('Markdown editor – image upload', { tag: ['@ce'] }, () => {
  test('Upload image via button shows local preview before submit', async ({ page }) => {
    const notesPage = new NotesPage(page);
    // const noteForm = new NoteFormPage(page);
    const formLocator = page.getByRole('heading', { name: 'Create a note' }).locator('../..');
    const contentImage = new MarkdownImageFieldPageModel(page, 'Content', formLocator);

    // Open note creation form
    await notesPage.goto();
    await notesPage.addNew();

    // Upload image through the markdown toolbar button
    await contentImage.uploadImageViaInput(TEST_IMAGE_PATH);

    // Verify temp token was inserted in editor (Write mode)
    const textarea = contentImage.getTextarea();
    await expect(textarea).toContainText('opencti-image://temp/');

    // Switch to Preview and confirm image is rendered (not broken/missing)
    await contentImage.switchToPreview();
    const previewImg = contentImage.getPreviewImage();
    await expect(previewImg).toBeVisible();

    // Image src should be a local blob: URL (not yet uploaded)
    const src = await previewImg.getAttribute('src');
    expect(src).toMatch(/^blob:/);
  });

  test('Submit persists image and re-edit shows backend storage URL', async ({ page }) => {
    const notesPage = new NotesPage(page);
    const noteForm = new NoteFormPage(page);
    const noteDetails = new NoteDetailsPage(page);
    const formLocator = page.getByRole('heading', { name: 'Create a note' }).locator('../..');
    const contentImage = new MarkdownImageFieldPageModel(page, 'Content', formLocator);

    // Open note creation form and fill abstract
    await notesPage.goto();
    await notesPage.addNew();

    await noteForm.abstractField.fill('E2E image upload test note');
    await noteForm.contentField.fill('Test Content Field Note e2e');

    // Upload image and verify temp token in editor
    await contentImage.uploadImageViaInput(TEST_IMAGE_PATH);
    await expect(contentImage.getTextarea()).toContainText('opencti-image://temp/');

    await noteForm.submit();

    // Submit form (triggers finalize: upload to storage + token rewrite)
    // await noteForm.submit();

    await page.getByRole('button', { name: 'Create' }).click();

    // // Open the created note

    await notesPage.getItemFromList('E2E image upload test note').click();
    await expect(noteDetails.getPage()).toBeVisible();

    // // In note detail view, MarkdownDisplay should render image from backend storage URL
    const noteContent = page.getByTestId('note-details-page');
    const persistedImg = noteContent.locator('img');
    await expect(persistedImg).toBeVisible();

    // Src must come from backend storage, not a blob URL
    const src = await persistedImg.getAttribute('src');
    expect(src).toMatch(/\/storage\/view\//);
  });
});
