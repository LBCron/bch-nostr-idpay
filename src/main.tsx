import React from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import { App } from './ui/App.js';

const container = document.getElementById('root');
if (!container) {
  throw new Error('Root mount element #root not found in index.html');
}

createRoot(container).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
