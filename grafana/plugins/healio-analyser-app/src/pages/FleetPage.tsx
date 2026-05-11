import React from 'react';
import { PluginPage } from '@grafana/runtime';

export default function FleetPage() {
  return (
    <PluginPage>
      <div style={{ padding: '20px' }}>
        <h1>Fleet Status</h1>

        <p>
          This page will display Falco agents, Sidekick health,
          dispatch targets, and node connectivity.
        </p>
      </div>
    </PluginPage>
  );
}
