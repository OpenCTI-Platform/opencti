const httpResponsePlugin = {
  requestDidStart: () => ({
    willSendResponse({ errors, response }) {
      if (response && response.http) {
        if (errors) {
          response.http.status = 200;
        }
      }
    },
  }),
};

export default httpResponsePlugin;
