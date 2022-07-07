Cypress.Cookies.debug(true);

describe('Assets', () => {
  before(function () {
    cy.fixture('users.json').then((user) => {
      this.user = user;
      cy.login(user.email, user.password);
    });
  });

  beforeEach(() => {
    Cypress.Cookies.preserveOnce('token', 'client_id', 'KEYCLOAK_IDENTITY', 'KEYCLOAK_SESSION');
  });

  describe('Devices', () => {
    it('Can list devices as cards', () => {
      cy.setCookie('view-devices', '{"sortBy":"name","orderAsc":true,"searchTerm":"","view":"cards","filters":{},"openExports":false,"numberOfElements":{"number":"1.1","symbol":"K","original":1103},"selectedElements":null,"selectAll":false,"openDeviceCreation":false}');
      cy.get('[data-cy="assets"]').click();
      cy.get('[data-cy="asset devices"]').click();
      cy.get('[data-cy="cards view"]').should('be.visible');
    });

    // it('Can list devices as lines', () => {
    //   cy.setCookie('view-devices', '{"sortBy":"name","orderAsc":true,"searchTerm":"","view":"lines","filters":{},"openExports":false,"numberOfElements":{"number":"1.1","symbol":"K","original":1103},"selectedElements":null,"selectAll":false,"openDeviceCreation":false}');
    //   cy.get('[data-cy="assets"]').click();
    //   cy.get('[data-cy="lines view"]').should('be.visible');
    // });
  });

  describe('Networks', () => {
    it('Can list networks as cards', () => {
      cy.setCookie('view-devices', '{"sortBy":"name","orderAsc":true,"searchTerm":"","view":"cards","filters":{},"openExports":false,"numberOfElements":{"number":"1.1","symbol":"K","original":1103},"selectedElements":null,"selectAll":false,"openDeviceCreation":false}');
      cy.get('[data-cy="assets"]').click();
      cy.get('[data-cy="asset networks"]').click();
      cy.get('[data-cy="cards view"]').should('be.visible');
    });

    // it('Can list networks as lines', () => {
    //   cy.setCookie('view-devices', '{"sortBy":"name","orderAsc":true,"searchTerm":"","view":"lines","filters":{},"openExports":false,"numberOfElements":{"number":"1.1","symbol":"K","original":1103},"selectedElements":null,"selectAll":false,"openDeviceCreation":false}');
    //   cy.get('[data-cy="assets"]').click();
    //   cy.get('[data-cy="lines view"]').should('be.visible');
    // });
  });

  describe('Software', () => {
    it('Can list software as cards', () => {
      cy.setCookie('view-devices', '{"sortBy":"name","orderAsc":true,"searchTerm":"","view":"cards","filters":{},"openExports":false,"numberOfElements":{"number":"1.1","symbol":"K","original":1103},"selectedElements":null,"selectAll":false,"openDeviceCreation":false}');
      cy.get('[data-cy="assets"]').click();
      cy.get('[data-cy="asset software"]').click();
      cy.get('[data-cy="cards view"]').should('be.visible');
    });

    // it('Can list software as lines', () => {
    //   cy.setCookie('view-devices', '{"sortBy":"name","orderAsc":true,"searchTerm":"","view":"lines","filters":{},"openExports":false,"numberOfElements":{"number":"1.1","symbol":"K","original":1103},"selectedElements":null,"selectAll":false,"openDeviceCreation":false}');
    //   cy.get('[data-cy="assets"]').click();
    //   cy.get('[data-cy="lines view"]').should('be.visible');
    // });
  });
});
