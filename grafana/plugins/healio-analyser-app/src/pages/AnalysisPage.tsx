import React, { useEffect, useState } from 'react';
import { PluginPage } from '@grafana/runtime';
import { Badge, Card, HorizontalGroup, Spinner, Alert } from '@grafana/ui';

interface ApiResponse {
  success: boolean;
  analysis?: {
    summary?: string;
    risk?: {
      severity?: string;
      confidence?: string;
      impact?: string;
    };
    mitre_attack?: {
      tactic?: string;
      technique_id?: string;
      technique_name?: string;
      sub_technique?: string | null;
    };
    investigate?: string[];
    mitigations?: {
      immediate?: string[];
      short_term?: string[];
      long_term?: string[];
    };
    false_positive?: {
      likelihood?: string;
      common_causes?: string[];
    };
  };
  threat_intel?: {
    has_threats?: boolean;
    highest_severity?: string;
    malicious_ips?: string[];
  };
}

const API_URL = '/api/analyze';

export default function AnalysisPage() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<ApiResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const response = await fetch(API_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            alert: 'test',
            rule: 'test',
            priority: 'Critical',
            hostname: 'falco-node',
            store: false,
          }),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const json: ApiResponse = await response.json();
        setData(json);
      } catch (err: any) {
        console.error(err);
        setError(err.message || 'Failed to fetch analysis');
      } finally {
        setLoading(false);
      }
    }

    load();
  }, []);

  const severity = data?.analysis?.risk?.severity || 'Unknown';
  const severityColor =
    severity === 'Critical' ? 'red' :
    severity === 'High'     ? 'orange' :
    severity === 'Medium'   ? 'blue' : 'green';

  return (
    <PluginPage>
      <div style={{ padding: '24px', maxWidth: 1200 }}>
        <h1 style={{ marginBottom: 24 }}>AI Security Analysis</h1>

        {loading && <Spinner size={32} />}

        {error && (
          <Alert title="API Error" severity="error" style={{ marginTop: 16 }}>
            {error}
          </Alert>
        )}

        {!loading && !error && !data && (
          <Alert title="No Data" severity="warning" style={{ marginTop: 16 }}>
            The API returned no data.
          </Alert>
        )}

        {!loading && data && (
          <>
            {/* Executive Summary */}
            <Card>
              <Card.Heading>Executive Summary</Card.Heading>
              <Card.Description>
                {data.analysis?.summary || 'No summary available.'}
              </Card.Description>
            </Card>

            {/* Badges */}
            <div style={{ marginTop: 20 }}>
              <HorizontalGroup>
                <Badge text={`Severity: ${severity}`} color={severityColor} />
                <Badge
                  text={`Confidence: ${data.analysis?.risk?.confidence || 'Unknown'}`}
                  color="blue"
                />
              </HorizontalGroup>
            </div>

            {/* MITRE ATT&CK */}
            <div style={{ marginTop: 20 }}>
              <Card>
                <Card.Heading>MITRE ATT&CK</Card.Heading>
                <Card.Description>
                  <div><strong>Tactic:</strong> {data.analysis?.mitre_attack?.tactic || 'N/A'}</div>
                  <div>
                    <strong>Technique:</strong>{' '}
                    {data.analysis?.mitre_attack?.technique_id || 'N/A'}{' '}
                    {data.analysis?.mitre_attack?.technique_name || ''}
                  </div>
                  <div>
                    <strong>Sub-technique:</strong>{' '}
                    {data.analysis?.mitre_attack?.sub_technique || 'N/A'}
                  </div>
                </Card.Description>
              </Card>
            </div>

            {/* Investigation Steps */}
            {data.analysis?.investigate && data.analysis.investigate.length > 0 && (
              <div style={{ marginTop: 20 }}>
                <Card>
                  <Card.Heading>Investigation Steps</Card.Heading>
                  <Card.Description>
                    {data.analysis.investigate.map((item, idx) => (
                      <div key={idx} style={{ marginBottom: 8 }}>
                        • {item}
                      </div>
                    ))}
                  </Card.Description>
                </Card>
              </div>
            )}

            {/* Mitigations */}
            {data.analysis?.mitigations && (
              <div style={{ marginTop: 20 }}>
                <Card>
                  <Card.Heading>Mitigations</Card.Heading>
                  <Card.Description>
                    {data.analysis.mitigations.immediate && data.analysis.mitigations.immediate.length > 0 && (
                      <>
                        <h4>Immediate</h4>
                        {data.analysis.mitigations.immediate.map((item, idx) => (
                          <div key={idx}>• {item}</div>
                        ))}
                      </>
                    )}

                    {data.analysis.mitigations.short_term && data.analysis.mitigations.short_term.length > 0 && (
                      <>
                        <h4 style={{ marginTop: 16 }}>Short Term</h4>
                        {data.analysis.mitigations.short_term.map((item, idx) => (
                          <div key={idx}>• {item}</div>
                        ))}
                      </>
                    )}

                    {data.analysis.mitigations.long_term && data.analysis.mitigations.long_term.length > 0 && (
                      <>
                        <h4 style={{ marginTop: 16 }}>Long Term</h4>
                        {data.analysis.mitigations.long_term.map((item, idx) => (
                          <div key={idx}>• {item}</div>
                        ))}
                      </>
                    )}
                  </Card.Description>
                </Card>
              </div>
            )}

            {/* Threat Intelligence */}
            {data.threat_intel && (
              <div style={{ marginTop: 20 }}>
                <Card>
                  <Card.Heading>Threat Intelligence</Card.Heading>
                  <Card.Description>
                    <div>
                      <strong>Threats Found:</strong>{' '}
                      {data.threat_intel.has_threats ? 'Yes' : 'No'}
                    </div>
                    <div>
                      <strong>Highest Severity:</strong>{' '}
                      {data.threat_intel.highest_severity || 'CLEAN'}
                    </div>
                    <div>
                      <strong>Malicious IPs:</strong>{' '}
                      {data.threat_intel.malicious_ips?.join(', ') || 'None'}
                    </div>
                  </Card.Description>
                </Card>
              </div>
            )}
          </>
        )}
      </div>
    </PluginPage>
  );
}
