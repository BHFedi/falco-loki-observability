import React, { useEffect, useState } from 'react';

import {
  Badge,
  Card,
  HorizontalGroup,
  Spinner,
} from '@grafana/ui';

import { PluginPage } from '@grafana/runtime';

interface ApiResponse {
  success: boolean;
  analysis: {
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

export default function AnalysisPage() {
  const [loading, setLoading] = useState(true);

  const [data, setData] = useState<ApiResponse | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const response = await fetch(
          'http://192.168.55.193:5000/api/analyze',
          {
            method: 'POST',

            headers: {
              'Content-Type': 'application/json',
            },

            body: JSON.stringify({
              alert: 'test',
              rule: 'test',
              priority: 'Critical',
              hostname: 'falco-node',
              store: false,
            }),
          }
        );

        const json = await response.json();

        console.log(json);

        setData(json);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }

    load();
  }, []);

  const severity = data?.analysis?.risk?.severity || 'Unknown';

  return (
    <PluginPage>
      <div style={{ padding: '24px' }}>
        <h1>AI Security Analysis</h1>

        {loading && <Spinner />}

        {!loading && data && (
          <>
            <Card>
              <Card.Heading>Executive Summary</Card.Heading>

              <Card.Description>
                {data.analysis.summary}
              </Card.Description>
            </Card>

            <div style={{ marginTop: '20px' }}>
              <HorizontalGroup>
                <Badge
                  text={`Severity: ${severity}`}
                  color={
                    severity === 'Critical'
                      ? 'red'
                      : severity === 'High'
                      ? 'orange'
                      : severity === 'Medium'
                      ? 'blue'
                      : 'green'
                  }
                />

                <Badge
                  text={`Confidence: ${data.analysis.risk?.confidence || 'Unknown'}`}
                  color="blue"
                />
              </HorizontalGroup>
            </div>

            <div style={{ marginTop: '20px' }}>
              <Card>
                <Card.Heading>MITRE ATT&CK</Card.Heading>

                <Card.Description>
                  <div>
                    <strong>Tactic:</strong>{' '}
                    {data.analysis.mitre_attack?.tactic || 'N/A'}
                  </div>

                  <div>
                    <strong>Technique:</strong>{' '}
                    {data.analysis.mitre_attack?.technique_id || 'N/A'}{' '}
                    {data.analysis.mitre_attack?.technique_name || ''}
                  </div>

                  <div>
                    <strong>Sub-technique:</strong>{' '}
                    {data.analysis.mitre_attack?.sub_technique || 'N/A'}
                  </div>
                </Card.Description>
              </Card>
            </div>

            <div style={{ marginTop: '20px' }}>
              <Card>
                <Card.Heading>Investigation Steps</Card.Heading>

                <Card.Description>
                  {data.analysis.investigate?.map((item) => (
                    <div key={item} style={{ marginBottom: '8px' }}>
                      • {item}
                    </div>
                  ))}
                </Card.Description>
              </Card>
            </div>

            <div style={{ marginTop: '20px' }}>
              <Card>
                <Card.Heading>Mitigations</Card.Heading>

                <Card.Description>
                  <h4>Immediate</h4>

                  {data.analysis.mitigations?.immediate?.map((item) => (
                    <div key={item}>• {item}</div>
                  ))}

                  <h4 style={{ marginTop: '16px' }}>Short Term</h4>

                  {data.analysis.mitigations?.short_term?.map((item) => (
                    <div key={item}>• {item}</div>
                  ))}

                  <h4 style={{ marginTop: '16px' }}>Long Term</h4>

                  {data.analysis.mitigations?.long_term?.map((item) => (
                    <div key={item}>• {item}</div>
                  ))}
                </Card.Description>
              </Card>
            </div>

            <div style={{ marginTop: '20px' }}>
              <Card>
                <Card.Heading>Threat Intelligence</Card.Heading>

                <Card.Description>
                  <div>
                    <strong>Threats Found:</strong>{' '}
                    {data.threat_intel?.has_threats ? 'Yes' : 'No'}
                  </div>

                  <div>
                    <strong>Highest Severity:</strong>{' '}
                    {data.threat_intel?.highest_severity || 'CLEAN'}
                  </div>

                  <div>
                    <strong>Malicious IPs:</strong>{' '}
                    {data.threat_intel?.malicious_ips?.join(', ') || 'None'}
                  </div>
                </Card.Description>
              </Card>
            </div>
          </>
        )}
      </div>
    </PluginPage>
  );
}
