import React from 'react';
import { PluginPage } from '@grafana/runtime';

export default function OverviewPage() {
  return (
    <PluginPage>
      <div style={{ padding: '20px' }}>
        <h1>Healio SIEM</h1>

        <p>Grafana-native AI investigation console.</p>

        <ul>
          <li>Falco alert investigations</li>
          <li>MITRE ATT&CK mapping</li>
          <li>Threat intelligence enrichment</li>
          <li>Fleet visibility</li>
        </ul>
      </div>
    </PluginPage>
  );
}
