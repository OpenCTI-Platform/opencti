describe('Assets', () => {
  beforeEach(function () {
    cy.fixture('users.json').then((user) => {
      this.user = user;
    });
    cy.visit('/');
  });

  it('Can list all devices', function () {
    cy.login(this.user.email, this.user.password);
    cy.url().should('eq', `${Cypress.config().baseUrl}/dashboard`);
    cy.get('[data-cy="assets"]').click();
    cy.url().should('eq', `${Cypress.config().baseUrl}/defender%20HQ/assets/devices?`);
    // TODO: Add hook to device cards and verify there's at least 1
  });

  it('Can list all networks', function () {
    cy.login(this.user.email, this.user.password);
    cy.get('[data-cy="assets"]').click();
    cy.get('[data-cy="asset networks"]').click();
    cy.url().should('eq', `${Cypress.config().baseUrl}/defender%20HQ/assets/network?`);
    // TODO: Add hook to network cards and verify there's at least 1
  });

  it('Can list all software', function () {
    cy.login(this.user.email, this.user.password);
    cy.get('[data-cy="assets"]').click();
    cy.get('[data-cy="asset software"]').click();
    cy.url().should('eq', `${Cypress.config().baseUrl}/defender%20HQ/assets/software?`);
    // TODO: Add hook to software cards and verify there's at least 1
  });
});
