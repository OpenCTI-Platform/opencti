import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource/geologica/400.css';
import '@fontsource/geologica/500.css';
import '@fontsource/geologica/600.css';
import '@fontsource/geologica/700.css';
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@filigran/design-system/dist/index.css';
import App from './app/App';
import './index.css';

createRoot(document.getElementById('root') as HTMLElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
