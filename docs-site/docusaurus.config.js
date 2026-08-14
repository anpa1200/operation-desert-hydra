// @ts-check
const {execFileSync} = require('node:child_process');

const landingPageSources = new Map([
  ['https://1200km.com/operation-desert-hydra/', 'src/pages/index.js'],
]);

function readGitDate(sourcePath) {
  try {
    const date = execFileSync(
      'git',
      ['log', '-1', '--format=%cs', '--', sourcePath],
      {cwd: __dirname, encoding: 'utf8'},
    ).trim();
    return /^\d{4}-\d{2}-\d{2}$/.test(date) ? date : undefined;
  } catch {
    return undefined;
  }
}

async function addLandingPageLastmod({defaultCreateSitemapItems, ...params}) {
  const items = await defaultCreateSitemapItems(params);
  return items.map((item) => {
    const sourcePath = landingPageSources.get(item.url);
    if (!sourcePath || item.lastmod) return item;
    const lastmod = readGitDate(sourcePath);
    return lastmod ? {...item, lastmod} : item;
  });
}

const config = {
  title: '1200km',
  tagline: 'AI-assisted CTI pipeline: MuddyWater public sources → OpenCTI → 11 validated detections → Kibana',
  favicon: 'img/ap-logo.png',
  url: 'https://1200km.com',
  baseUrl: '/operation-desert-hydra/',
  scripts: [{src: 'https://1200km.com/assets/docusaurus-ecosystem.js?v=20260614-3', defer: true}],
  organizationName: 'anpa1200',
  projectName: 'operation-desert-hydra',

  trailingSlash: true,
  onBrokenLinks: 'warn',
  markdown: {hooks: {onBrokenMarkdownLinks: 'warn'}},
  i18n: {defaultLocale: 'en', locales: ['en']},
  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/anpa1200/operation-desert-hydra/tree/main/docs-site/',
          showLastUpdateTime: true,
        },
        blog: false,
        sitemap: {
          lastmod: 'date',
          createSitemapItems: addLandingPageLastmod,
        },
        gtag: {trackingID: 'G-TMTG21RVHM', anonymizeIP: true},
        theme: {customCss: './src/css/custom.css'}
      }
    ]
  ],
  themeConfig: {
    image: 'img/cover.png',
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: false,
    },
    metadata: [
      {
        property: 'og:site_name',
        content: '1200km — Andrey Pautov Security Research',
      },
      {
        name: 'keywords',
        content: 'Operation Desert Hydra, MuddyWater, Seedworm, CTI pipeline, MITRE ATT&CK, detection engineering, OpenCTI, Kibana detections, SIEM rules, Iran threat actor, MOIS, Sysmon, Winlogbeat, lab-validated detection',
      },
    ],
    navbar: {
      title: 'Operation Desert Hydra',
      logo: {
        alt: 'Andrey Pautov',
        src: 'img/ap-logo.png',
      },
      items: [
        {type: 'docSidebar', sidebarId: 'hydra', position: 'left', label: 'Pipeline'},
        {href: 'https://1200km.com/', label: 'Main Page', position: 'left'},
        {label: 'Projects', position: 'right', items: [
          {label: 'CTI Analyst Field Manual', href: 'https://1200km.com/cti-analyst-field-manual/'},
          {label: 'CTI as a Code', href: 'https://1200km.com/CTI_as_a_Code/'},
          {label: 'Customer-Driven AI CTI', href: 'https://1200km.com/customer-driven-ai-cti-project/'},
          {label: 'Israel Threat Actors CTI', href: 'https://1200km.com/israel-government-threat-actors-cti/'},
          {label: 'AI vs Defense', href: 'https://1200km.com/ai-vs-defense/'},
          {label: 'HexStrike AI (upstream project)', href: 'https://github.com/0x4m4/hexstrike-ai'},
          {label: 'AdversaryGraph Docs', href: 'https://1200km.com/adversarygraph-docs/'}
        ]},
        {label: 'Medium Article', href: 'https://medium.com/@1200km/operation-desert-hydra-ai-assisted-cti-pipeline-muddywater-to-kibana-34da7917acf0', position: 'right'},
        {href: 'https://github.com/anpa1200/operation-desert-hydra', label: 'GitHub', position: 'right'},
        {href: 'https://1200km.com/', label: 'Main Page', position: 'right', className: 'navbar-portfolio-btn'}
      ]
    },
    footer: {
      style: 'dark',
      links: [
        {title: 'Pipeline', items: [
          {label: 'Introduction', to: '/docs/intro'},
          {label: 'The Pipeline', to: '/docs/pipeline'},
          {label: 'Detection Atlas', to: '/docs/phase-4-detection-atlas'},
          {label: 'Validation Results', to: '/docs/phase-5-results'}
        ]},
        {title: 'Ecosystem', items: [
          {label: 'CTI Analyst Field Manual', href: 'https://1200km.com/cti-analyst-field-manual/'},
          {label: 'CTI as a Code', href: 'https://1200km.com/CTI_as_a_Code/'},
          {label: 'Customer-Driven AI CTI', href: 'https://1200km.com/customer-driven-ai-cti-project/'},
          {label: 'Israel Threat Actors CTI', href: 'https://1200km.com/israel-government-threat-actors-cti/'},
          {label: 'AI vs Defense', href: 'https://1200km.com/ai-vs-defense/'},
          {label: 'HexStrike AI (upstream project)', href: 'https://github.com/0x4m4/hexstrike-ai'},
          {label: 'AdversaryGraph Docs', href: 'https://1200km.com/adversarygraph-docs/'}
        ]},
        {title: 'Author', items: [
          {label: 'Medium', href: 'https://medium.com/@1200km'},
          {label: 'GitHub', href: 'https://github.com/anpa1200'},
          {label: 'LinkedIn', href: 'https://www.linkedin.com/in/andrey-pautov/'}
        ]}
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Andrey Pautov. Operation Desert Hydra — AI-Assisted CTI Pipeline.`
    },
    prism: {theme: require('prism-react-renderer').themes.github, darkTheme: require('prism-react-renderer').themes.dracula}
  }
};
module.exports = config;
