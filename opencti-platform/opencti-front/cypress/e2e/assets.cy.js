Cypress.Cookies.debug(true);

describe('Assets', () => {
  before(function () {
    cy.fixture('users.json').then((user) => {
      this.user = user;
      cy.visit('/');
      cy.login(user.email, user.password);
    });
  });

  beforeEach(() => {
    Cypress.Cookies.preserveOnce('token', 'client_id');
  });

  describe('Devices', () => {
    beforeEach(() => {
      cy.visit('/defender%20HQ/assets/devices?');
    });

    it('Can list devices as cards', () => {
      cy.setCookie('view-devices', '{"sortBy":"name","orderAsc":true,"searchTerm":"","view":"cards","filters":{},"openExports":false,"numberOfElements":{"number":"1.1","symbol":"K","original":1103},"selectedElements":null,"selectAll":false,"openDeviceCreation":false}');
      // cy.visit('/defender%20HQ/assets/devices?');
      cy.expect('[data-cy="lines view"]')
        .to.be.visible();
      // cy.getCookie('view-devices');
    });

    // it('Can list devices as lines', () => {
    //   cy.visit('/defender%20HQ/assets/devices?');
    // });
  });

  // describe('Networks', () => {
  //   it('Can list networks as cards', () => {
  //     cy.visit('/defender%20HQ/assets/network?');
  //   });

  //   it('Can list networks as lines', () => {
  //     cy.visit('/defender%20HQ/assets/network?');
  //   });
  // });

  // describe('Software', () => {
  //   it('Can list software as cards', () => {
  //     cy.visit('/defender%20HQ/assets/software?');
  //   });

  //   it('Can list software as lines', () => {
  //     cy.visit('/defender%20HQ/assets/software?');
  //   });
  // });

  // it('Can list all devices', function () {
  //   cy.login(this.user.email, this.user.password);
  //   cy.url().should('eq', `${Cypress.config().baseUrl}/dashboard`);
  //   cy.get('[data-cy="assets"]').click();
  //   cy.url().should('eq', `${Cypress.config().baseUrl}/defender%20HQ/assets/devices?`);
  // });

  // it('Can list all networks', function () {
  //   cy.login(this.user.email, this.user.password);
  //   cy.get('[data-cy="assets"]').click();
  //   cy.get('[data-cy="asset networks"]').click();
  //   cy.url().should('eq', `${Cypress.config().baseUrl}/defender%20HQ/assets/network?`);
  //   // TODO: Add hook to network cards and verify there's at least 1
  // });

  // it('Can list all software', function () {
  //   cy.login(this.user.email, this.user.password);
  //   cy.get('[data-cy="assets"]').click();
  //   cy.get('[data-cy="asset software"]').click();
  //   cy.url().should('eq', `${Cypress.config().baseUrl}/defender%20HQ/assets/software?`);
  //   // TODO: Add hook to software cards and verify there's at least 1
  // });
});
