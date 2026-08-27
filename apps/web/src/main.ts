import { mount } from 'svelte';
import App from './App.svelte';
import { registerServiceWorker } from './lib/pwa/register';

const target = document.getElementById('app');
if (!target) {
  throw new Error('missing #app mount point');
}

const app = mount(App, { target });

registerServiceWorker();

export default app;
