import path from 'path';
import { pathToFileURL } from 'url';
import axios from 'axios';
import { chromium } from '@playwright/test';

const fs = require('fs');

function getAllDirectories(directoryPath) {
  // Read the contents of the directory
  const contents = fs.readdirSync(directoryPath);

  // Filter out only directories
  const directories = contents.filter((item) => {
    const itemPath = path.join(directoryPath, item);
    return fs.statSync(itemPath).isDirectory();
  });

  return directories;
}

function convertImageToBase64(filePath) {
  try {
    const imageData = fs.readFileSync(filePath);
    const base64Image = `data:image/png;base64,${imageData.toString('base64')}`;
    return base64Image;
  } catch (err) {
    console.error('Error:', err);
    return null;
  }
}

// Example usage

export default async (reportData) => {
  // https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=dotnet

  // do not store your webhook url in the source code, but pass your webhook url from environment variables
  const url = process.env.TEAMS_WEBHOOK;

  const failedImage = [];
  const {
    name, dateH, durationH, summary, htmlPath,
  } = reportData;

  console.log('launch browser ...');
  // dataUrl image can NOT zoomin in Teams https://github.com/MicrosoftDocs/msteams-docs/issues/7427
  // so just take a small screenshot on pie chart
  const browser = await chromium.launch({
    // headless: false
  });

  console.log('new page ...');
  const page = await browser.newPage();
  await page.setViewportSize({
    width: 860,
    height: 1060,
  });

  const htmlUrl = pathToFileURL(path.resolve(htmlPath)).toString();
  console.log(`open ${htmlUrl} ...`);
  await page.goto(htmlUrl);

  await new Promise((resolve) => {
    setTimeout(resolve, 500);
  });

  await page.evaluate(() => {
    location.hash = 'page=report';
    window.postMessage({
      flyoverWidth: '100%',
    });
  });

  await new Promise((resolve) => {
    setTimeout(resolve, 500);
  });

  console.log('take screenshot ...');

  // const screenshot = await page.screenshot();

  // Teams can NOT zoom in the image, just take a small screenshot
  const pie = page.locator('.mcr-pie-chart svg');
  const screenshot = await pie.screenshot();

  await page.close();
  await browser.close();

  const dataUrl = `data:image/png;base64,${screenshot.toString('base64')}`;
  // console.log(dataUrl);

  const title = `${name} ${dateH} (${durationH})`;

  const facts = ['tests', 'passed', 'flaky', 'skipped', 'failed'].map((k) => {
    const item = summary[k];
    const percent = item.percent ? ` (${item.percent})` : '';
    return {
      title: item.name,
      value: `${item.value} ${percent}`,
    };
  });

  console.log(facts);

  let description = '';
  if (summary.passed.value === summary.tests.value) {
    description = '✔ Congratulations! All tests passed.';
  } else if (summary.failed.value > 0) {
    // @owners of all failed cases
    const directoryPath = path.resolve(htmlPath).replace('report.html', '');
    const directories = getAllDirectories(directoryPath);
    description = '✗ The e2e test failed';
    directories.forEach((directory) => {
      description += `\\\n - ${directory}`;
      const imagePath = path.join(directoryPath, directory, 'test-failed-1.png');
      const base64Image = convertImageToBase64(imagePath);
      if (!base64Image) {
        console.log('Failed to convert the image to base64 for', directory);
      }
      failedImage.push({
        type: 'Image',
        url: base64Image,
        width: '360px',
        altText: directory,
        msTeams: {
          allowExpand: true,
        },
      });
    });
  }

  console.log(description);

  // https://adaptivecards.io/explorer/AdaptiveCard.html
  const data = {
    type: 'message',
    attachments: [{
      contentType: 'application/vnd.microsoft.card.adaptive',
      content: {
        type: 'AdaptiveCard',
        body: [{
          type: 'TextBlock',
          size: 'medium',
          weight: 'bolder',
          text: title,
          style: 'heading',
          wrap: true,
        }, {
          type: 'Image',
          url: dataUrl,
          width: '360px',
          altText: 'Pie chart',
          msTeams: {
            allowExpand: true,
          },
        },
        ...failedImage,
        {
          type: 'FactSet',
          facts,
        }, {
          type: 'TextBlock',
          text: description,
          wrap: true,
        }],
        $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
        version: '1.2',
      },
    }],
  };

  await axios.post(url, data).catch((err) => {
    // console.log(err);
    console.log(err.message);
    console.log('[teams] failed to post message to Teams channel');
  });
};
