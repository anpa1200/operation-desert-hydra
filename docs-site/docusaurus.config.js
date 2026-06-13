// @ts-check
const config = {
  title: 'Operation Desert Hydra',
  tagline: 'AI-assisted CTI pipeline: MuddyWater public sources → OpenCTI → 11 validated detections → Kibana',
  favicon: 'img/ap-logo.png',
  url: 'https://1200km.com',
  baseUrl: '/operation-desert-hydra/',
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
          editUrl: 'https://github.com/anpa1200/operation-desert-hydra/tree/main/docs-site/'
        },
        blog: false,
        gtag: {trackingID: 'G-TMTG21RVHM', anonymizeIP: true},
        theme: {customCss: './src/css/custom.css'}
      }
    ]
  ],
  themeConfig: {
    image: 'img/logo.png',
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: false,
    },
    metadata: [
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
          {label: 'HexStrike AI', href: 'https://github.com/0x4m4/hexstrike-ai'},
          {label: 'ThreatMapper Docs', href: 'https://1200km.com/threatmapper-docs/'}
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
          {label: 'HexStrike AI', href: 'https://github.com/0x4m4/hexstrike-ai'},
          {label: 'ThreatMapper Docs', href: 'https://1200km.com/threatmapper-docs/'}
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
