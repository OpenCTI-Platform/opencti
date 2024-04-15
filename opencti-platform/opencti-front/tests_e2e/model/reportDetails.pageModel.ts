import { Page } from '@playwright/test';

export default class ReportDetailsPage {
  constructor(private page: Page) {}

  getReportDetailsPage() {
    return this.page.getByTestId('report-details-page');
  }

  getOneReport(name: string) {
    return this.page.getByRole('link', { name });
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getEditButton() {
    return this.page.getByLabel('Edit');
  }

  getExportButton() {
    return this.page.getByLabel('Quick export');
  }

  // getObservablesTab() {
  //   return this.page.getByRole('tab', { name: 'Observables' });
  // }
  //
  // getPopAlert(name: string) {
  //   return this.page.getByRole('alert', { name });
  // }
  //
  // getDataTab() {
  //   return this.page.getByRole('tab', { name: 'Data' });
  // }

  getDataList(name: string) {
    return this.page.getByRole('list', { name });
  }

  // getNewFile() {
  //   let previousCount = 0;
  //   const checkInterval = setInterval(async () => {
  //     const rows = await this.page.$$('.table-row');
  //     if (rows.length !== previousCount) {
  //       console.log(`Le nombre de lignes a changé. Nouveau nombre de lignes : ${rows.length}`);
  //       previousCount = rows.length;
  //     }
  //   }, 1000); // Vérifie chaque seconde
  //   // Pour arrêter l'intervalle après un certain temps
  //   setTimeout(() => {
  //     clearInterval(checkInterval);
  //   }, 10000); // Arrête après 10 secondes
  // }
}
