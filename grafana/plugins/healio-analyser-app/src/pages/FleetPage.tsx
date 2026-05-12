import React, { useEffect, useState } from 'react';
import { PluginPage } from '@grafana/runtime';
import { Card, Spinner, Alert, Badge } from '@grafana/ui';

const API_URL = '/api/fleet/status';

interface Target {
  label: string;
  url: string;
  auth: boolean;
}

export default function FleetPage() {
  const [loading, setLoading] = useState(true);
  const [targets, setTargets] = useState<Target[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(API_URL)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => setTargets(data.targets || []))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <PluginPage>
      <div style={{ padding: '24px' }}>
        <h1>Fleet Status</h1>

        {loading && <Spinner size={32} />}
        {error && <Alert title="Error" severity="error">{error}</Alert>}

        {!loading && !error && targets.length === 0 && (
          <Alert title="No Targets" severity="info">
            No fleet targets are currently registered.
          </Alert>
        )}

        {!loading && targets.map((t, i) => (
          <div key={i} style={{ marginTop: 16 }}>
            <Card>
              <Card.Heading>{t.label}</Card.Heading>
              <Card.Description>
                <div style={{ marginBottom: 4 }}><strong>URL:</strong> {t.url}</div>
                <div>
                  <Badge
                    text={t.auth ? 'Auth Enabled' : 'No Auth'}
		    color={t.auth ? 'green' : 'orange'}
                  />
                </div>
              </Card.Description>
            </Card>
          </div>
        ))}
      </div>
    </PluginPage>
  );
}
