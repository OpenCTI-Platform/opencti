import { ArtifactPage} from "../model/Artifact.pageModel";
import { ArtifactImportPage} from "../model/ArtifactImport.pageModel";
import { expect, test } from "../fixtures/baseFixtures";


test('Validate a new artifact file', async ({ page }) => {
        const artifactPage = new ArtifactPage(page);
        const artifactImport = new ArtifactImportPage(page);
        await page.goto('/dashboard/observations/artifacts')
        await artifactPage.addNewArtifactImport().click();
        artifactImport.getFileInput();
        // await artifactImport.fillFileInput('File');
        await artifactImport.getCreateArtifactImportButton().click();
        await expect (artifactImport.getErrorMessage()).toBeVisible();
})