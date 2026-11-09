import { render } from 'preact';
import { App } from './App';
import './styles.css';

const root = document.getElementById('root') || document.body;
render(<App />, root);

if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  });
}
