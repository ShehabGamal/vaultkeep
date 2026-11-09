import { render } from 'preact';
import { App } from './App';
import './styles.css';

const root = document.getElementById('root') || document.body;
render(<App />, root);
