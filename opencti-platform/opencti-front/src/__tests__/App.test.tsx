import React, { Suspense } from 'react';
import ReactDOM from 'react-dom';
import { RelayEnvironmentProvider } from 'react-relay/hooks';
import App from '../app';
import { environment } from '../relay/environment';

it('renders without crashing', () => {
  const div = document.createElement('div');
  ReactDOM.render(
    <RelayEnvironmentProvider environment={environment}>
      <Suspense fallback={'Loading...'}>
        <App />
      </Suspense>
    </RelayEnvironmentProvider>,
    div,
  );
  ReactDOM.unmountComponentAtNode(div);
});
