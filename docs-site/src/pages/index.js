import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import styles from './index.module.css';

const phases = [
  ['Phase 1: Source Gathering', 'AI-assisted deep research across 71 candidate sources. Parallel Gemini + OpenAI passes, review gate, 8 government/vendor sources promoted.', '/docs/phase-1-source-gathering'],
  ['Phase 2: Procedure Dataset', '10 source-bound procedure records with evidence labels (Observed/Reported/Assessed), ATT&CK mappings, and detection opportunity notes.', '/docs/phase-2-procedure-dataset'],
  ['Phase 3: OpenCTI', 'Self-hosted OpenCTI 6.2 knowledge graph: MuddyWater intrusion set, 9 malware, 4 tools, 21 ATT&CK techniques, 20 source reports.', '/docs/phase-3-opencti'],
  ['Phase 4: Detection Atlas', '11 detection records with SIEM-agnostic pseudologic, coverage scores, false positive classes, and design rationale.', '/docs/phase-4-detection-atlas'],
  ['Phase 5: Validation Lab', 'One-command lab: Docker + Vagrant Windows 10 VM + Ansible provisioning. 11 benign simulations, 12 Kibana proof screenshots.', '/docs/phase-5-validation-lab'],
  ['Phase 6: Coverage Matrix', '21 procedure techniques + 7 from source set. 16 techniques (76%) fully validated. 6 capability gates that determine your effective coverage floor.', '/docs/phase-6-coverage-matrix'],
];

export default function Home() {
  return (
    <Layout title="Operation Desert Hydra" description="AI-assisted CTI pipeline: MuddyWater public sources → OpenCTI → 11 detection records → 14 PASS / 1 PARTIAL / 1 FAIL across 16 rule checks → Kibana.">
      <header className="hero hero--hydra">
        <div className="container" style={{textAlign: 'center'}}>
          <h1 className="hero__title">Operation Desert Hydra</h1>
          <p className="hero__subtitle">AI-assisted CTI pipeline: MuddyWater public sources → OpenCTI → 11 detection records → 14 PASS / 1 PARTIAL / 1 FAIL across 16 rule checks → Kibana</p>
          <div style={{marginBottom: '1.5rem'}}>
            <Link className="button button--secondary button--lg" to="/docs/intro">View the Pipeline</Link>
            {' '}
            <Link className="button button--outline button--secondary button--lg" href="https://github.com/anpa1200/operation-desert-hydra">GitHub Repo</Link>
          </div>
          <img
            src="/operation-desert-hydra/img/cover.png"
            alt="Operation Desert Hydra: CTI Pipeline"
            className="cover-image"
          />
        </div>
      </header>
      <main>
        <section className="manual-section">
          <div className="container">
            <h2>What This Is</h2>
            <p>
              Operation Desert Hydra is a complete CTI-to-detection pipeline focused on <strong>MuddyWater / Seedworm</strong> — widely reported by government and vendor sources as Iran-linked activity associated with MOIS, targeting Israeli government, defense, and critical infrastructure. The pipeline enforces a full chain: public sources → structured procedures → OpenCTI knowledge graph → detection rules → benign lab simulation → Kibana proof screenshots.
            </p>
            <p>
              Everything is on GitHub: <a href="https://github.com/anpa1200/operation-desert-hydra">github.com/anpa1200/operation-desert-hydra</a>. One repository contains everything needed to reproduce the full pipeline from a clean machine.
            </p>
          </div>
        </section>

        <section className="manual-section" style={{background: 'var(--ifm-background-surface-color)'}}>
          <div className="container">
            <h2>The Pipeline — 6 Phases</h2>
            <div className="manual-grid">
              {phases.map(([title, body, href]) => (
                <article className="manual-card" key={title}>
                  <h3>{title}</h3>
                  <p>{body}</p>
                  <Link to={href}>Read phase</Link>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="manual-section">
          <div className="container">
            <h2>Key Results</h2>
            <div className="manual-grid">
              <article className="manual-card">
                <h3>Validation: 14 PASS / 1 PARTIAL / 1 FAIL</h3>
                <p>16 rule checks across 11 detection records — some detections have multiple rules tested separately. Every PASS has a Kibana screenshot. Failures are documented with root cause and fix path. 9 of 11 detections have coverage score ≥ 4 (lab-validated).</p>
              </article>
              <article className="manual-card">
                <h3>11 Detection Records</h3>
                <p>SIEM-agnostic pseudologic (Sigma, KQL, Elastic JSON, SPL). Coverage scores: 5 = lab-validated multi-source, 4 = lab-validated single-source, 3 = validation incomplete or failed (documented reason). 9 detections score ≥ 4; 2 score 3.</p>
              </article>
              <article className="manual-card">
                <h3>8 Promoted Sources</h3>
                <p>From 71 AI-assisted candidate sources, 8 government and vendor sources survived the analyst review gate: CISA AA22-055A, INCD 2023, INCD 2024, and five supporting vendor sources.</p>
              </article>
              <article className="manual-card">
                <h3>21 ATT&CK Techniques (procedure dataset)</h3>
                <p>Mapped across 8 tactics. 16 techniques (76%) fully lab-validated. 6 capability gates determine your effective coverage floor.</p>
              </article>
            </div>
          </div>
        </section>

        <section className="manual-section" style={{background: 'var(--ifm-background-surface-color)'}}>
          <div className="container">
            <h2>Reproduce It</h2>
            <p>Deploy the full stack from a single command:</p>
            <pre style={{background: '#1e1e1e', color: '#d4d4d4', padding: '1rem', borderRadius: '6px', overflowX: 'auto'}}>
              {`git clone https://github.com/anpa1200/operation-desert-hydra.git
cd operation-desert-hydra
cp stack/.env.template stack/.env
# fill in ELASTIC_PASSWORD, OPENCTI_ADMIN_PASSWORD, OPENCTI_ADMIN_TOKEN
bash start.sh
# → OpenCTI: http://localhost:8080
# → Kibana:  http://localhost:5601`}
            </pre>
            <p>Prerequisites: Docker, VirtualBox, Vagrant, Ansible, Python 3 + pywinrm. All 11 simulations run automatically (~10 min).</p>
            <Link className="button button--primary" to="/docs/reproduce">Full Reproduce Instructions</Link>
          </div>
        </section>

        <section className="manual-section">
          <div className="container">
            <h2>Related Projects</h2>
            <div className="manual-grid">
              <article className="manual-card">
                <h3>CTI Analyst Field Manual</h3>
                <p>Practitioner tradecraft: PIRs, evidence handling, attribution, source reliability, infrastructure pivoting, hunting hypotheses, detection backlog, SOC handoff, and 10 reusable analyst templates.</p>
                <a href="https://anpa1200.github.io/cti-analyst-field-manual/">Open Manual</a>
              </article>
              <article className="manual-card">
                <h3>Israel Government Threat Actors CTI</h3>
                <p>Defensive knowledge base for threat actors targeting Israeli government, public-sector, critical infrastructure, and adjacent suppliers. Actor profiles, ATT&amp;CK mappings, and detection examples. Blue-team only.</p>
                <a href="https://anpa1200.github.io/israel-government-threat-actors-cti/">Open Project</a>
              </article>
              <article className="manual-card">
                <h3>Customer-Driven AI CTI</h3>
                <p>Gate-controlled CTI-to-detection delivery methodology from customer requirements and PIRs/SIRs to detection backlog, SOC handoff, and measurable defensive outcomes.</p>
                <a href="https://anpa1200.github.io/customer-driven-ai-cti-project/">Open Project</a>
              </article>
              <article className="manual-card">
                <h3>OpenCTI Intelligent Shield</h3>
                <p>OpenCTI platform with Claude-powered enrichment connector: STIX 2.1 workflows, confidence-scored IOC enrichment, and an analyst gate before any object enters the graph.</p>
                <a href="https://github.com/anpa1200/opencti-intelligent-shield">GitHub</a>
              </article>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
