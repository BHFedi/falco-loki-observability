import React from 'react';
import { PluginPage } from '@grafana/runtime';

export default function ThreatIntelPage() {
  return (
    <PluginPage>
      <div style={{ padding: '20px' }}>
        <h1>Threat Intelligence</h1>

        <p>
          IP reputation feeds, ThreatFox matches,
          IOC lookups, and feed statistics.
        </p>
      </div>
    </PluginPage>
  );
}
