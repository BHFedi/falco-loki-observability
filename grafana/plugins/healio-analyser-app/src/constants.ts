import pluginJson from './plugin.json';

export const PLUGIN_BASE_URL = `/a/${pluginJson.id}`;

export const ROUTES = {
  Home: '/',
  Analysis: '/analysis',
  Fleet: '/fleet',          // ← was 'History: '/history'' — MUST match plugin.json
  ThreatIntel: '/threatintel',
};
