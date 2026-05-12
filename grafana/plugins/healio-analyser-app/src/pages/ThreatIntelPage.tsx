import React, { useEffect, useState } from 'react';
import { PluginPage } from '@grafana/runtime';
import { Card, Spinner, Alert, Badge, HorizontalGroup } from '@grafana/ui';

const API_URL = '/api/threatintel/stats';

export default function ThreatIntelPage() {
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(API_URL)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => setStats(data))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const feeds = stats?.feeds_loaded ? Object.entries(stats.feeds_loaded) : [];

  return (
    <PluginPage>
      <div style={{ padding: '24px' }}>
        <h1>Threat Intelligence</h1>

        {loading && <Spinner size={32} />}
        {error && <Alert title="Error" severity="error">{error}</Alert>}

        {!loading && stats && (
          <>
            <HorizontalGroup style={{ marginTop: 16 }}>
              <Badge text={`Total IPs: ${stats.total_ips ?? 0}`} color="blue" />
              <Badge text={`Spamhaus CIDRs: ${stats.spamhaus_cidrs ?? 0}`} color="orange" />
              <Badge text={`Feeds: ${feeds.length}`} color="green" />
            </HorizontalGroup>

            <div style={{ marginTop: 24 }}>
              <Card>
                <Card.Heading>Feed Status</Card.Heading>
                <Card.Description>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ textAlign: 'left', borderBottom: '2px solid #444' }}>
                        <th style={{ padding: 8 }}>Feed</th>
                        <th style={{ padding: 8 }}>Count</th>
                        <th style={{ padding: 8 }}>Updated</th>
                      </tr>
                    </thead>
                    <tbody>
                      {feeds.map(([name, info]: [string, any]) => (
                        <tr key={name} style={{ borderBottom: '1px solid #333' }}>
                          <td style={{ padding: 8 }}>{name}</td>
                          <td style={{ padding: 8 }}>{info.count ?? 0}</td>
                          <td style={{ padding: 8, color: '#888' }}>{info.updated || 'never'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Card.Description>
              </Card>
            </div>
          </>
        )}
      </div>
    </PluginPage>
  );
}
