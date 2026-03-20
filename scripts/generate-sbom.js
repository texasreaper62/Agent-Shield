'use strict';

/**
 * Generate a CycloneDX-compatible Software Bill of Materials (SBOM).
 *
 * Agent Shield has zero runtime dependencies, so this SBOM reflects only
 * the package itself and any devDependencies used during development.
 */

const fs = require('fs');
const path = require('path');

const pkg = require('../package.json');

const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${generateUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [
      {
        vendor: 'agent-shield',
        name: 'sbom-generator',
        version: '1.0.0'
      }
    ],
    component: {
      type: 'library',
      name: pkg.name,
      version: pkg.version,
      description: pkg.description,
      licenses: [{ license: { id: pkg.license } }],
      purl: `pkg:npm/${pkg.name}@${pkg.version}`
    }
  },
  components: [],
  dependencies: [
    {
      ref: `pkg:npm/${pkg.name}@${pkg.version}`,
      dependsOn: []
    }
  ]
};

// Add devDependencies as components (runtime has zero deps)
if (pkg.devDependencies) {
  for (const [name, version] of Object.entries(pkg.devDependencies)) {
    const cleanVersion = version.replace(/^[\^~>=<]/, '');
    sbom.components.push({
      type: 'library',
      name,
      version: cleanVersion,
      scope: 'optional',
      purl: `pkg:npm/${name}@${cleanVersion}`,
      description: `Development dependency (not shipped to users)`
    });
  }
}

const outputPath = path.join(__dirname, '..', 'sbom.json');
fs.writeFileSync(outputPath, JSON.stringify(sbom, null, 2) + '\n');
console.log(`[Agent Shield] SBOM generated: ${outputPath}`);
console.log(`[Agent Shield] Runtime dependencies: 0`);
console.log(`[Agent Shield] Dev dependencies: ${sbom.components.length}`);

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
