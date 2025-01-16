import { MESSAGING$ } from '../relay/environment';

/**
 * Starts download of a file at given URL, saving it under a given name.
 *
 * @param url original URL to fetch from
 * @param filename the final name for the downloaded file
 */
async function downloadAs(url: string, filename: string): Promise<void> {
  try {
    // Fetch the file
    const response = await fetch(url);

    // Check if the response is OK
    if (!response.ok) {
      MESSAGING$.notifyError(`Failed to fetch file. HTTP status: ${response.status}`);
    }

    // Get the file as a Blob
    const blob = await response.blob();

    // Create a temporary URL for the Blob
    const blobUrl = URL.createObjectURL(blob);

    // Create a hidden anchor element
    const anchor = document.createElement('a');
    anchor.href = blobUrl;
    anchor.download = filename; // Force the desired filename
    document.body.appendChild(anchor); // Append to the DOM temporarily
    anchor.click(); // Trigger the download
    document.body.removeChild(anchor); // Clean up

    // Release the Blob URL to free memory
    URL.revokeObjectURL(blobUrl);
  } catch (error) {
    MESSAGING$.notifyError(`Failed to download file. Error: ${error}`);
  }
}

export default downloadAs;
