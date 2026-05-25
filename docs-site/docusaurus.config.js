// @ts-check
const config = {
  title: 'Operation Desert Hydra',
  tagline: 'AI-assisted CTI pipeline: MuddyWater public sources → OpenCTI → 11 validated detections → Kibana',
  favicon: 'img/ap-logo.png',
  url: 'https://anpa1200.github.io',
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
        theme: {customCss: './src/css/custom.css'}
      }
    ]
  ],
  themeConfig: {
    navbar: {
      title: 'Operation Desert Hydra',
      logo: {
        alt: 'Andrey Pautov',
        src: 'img/ap-logo.png',
      },
      items: [
        {type: 'docSidebar', sidebarId: 'hydra', position: 'left', label: 'Pipeline'},
        {href: 'https://anpa1200.github.io/', label: 'Portfolio', position: 'left'},
        {label: 'Projects', position: 'right', items: [
          {label: 'Field Manual', href: 'https://anpa1200.github.io/cti-analyst-field-manual/'},
          {label: 'Customer-Driven AI CTI', href: 'https://anpa1200.github.io/customer-driven-ai-cti-project/'},
          {label: 'Israel Threat Actors CTI', href: 'https://anpa1200.github.io/israel-government-threat-actors-cti/'},
          {label: 'HexStrike AI', href: 'https://github.com/0x4m4/hexstrike-ai'}
        ]},
        {label: 'Medium Article', href: 'https://medium.com/@1200km/operation-desert-hydra-ai-assisted-cti-pipeline-muddywater-to-kibana-34da7917acf0', position: 'right'},
        {href: 'https://github.com/anpa1200/operation-desert-hydra', label: 'GitHub', position: 'right'},
        {href: 'https://anpa1200.github.io/', label: 'All Projects', position: 'right', className: 'navbar-portfolio-btn'}
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
          {label: 'Field Manual', href: 'https://anpa1200.github.io/cti-analyst-field-manual/'},
          {label: 'Customer-Driven AI CTI', href: 'https://anpa1200.github.io/customer-driven-ai-cti-project/'},
          {label: 'Israel Threat Actors CTI', href: 'https://anpa1200.github.io/israel-government-threat-actors-cti/'},
          {label: 'HexStrike AI', href: 'https://github.com/0x4m4/hexstrike-ai'}
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
