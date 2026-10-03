const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');

  // 1. Create or find default operator
  const hashedPassword = await bcrypt.hash('Operator2024!', 10);
  const user = await prisma.user.upsert({
    where: { email: 'operator@cybersploi.io' },
    update: {},
    create: {
      email: 'operator@cybersploi.io',
      username: 'cybersploi_operator',
      firstName: 'Cyber',
      lastName: 'Operator',
      password: hashedPassword,
      emailVerified: true
    }
  });
  console.log(`✅ User ready: ${user.email} (${user.id})`);

  // 2. Create or find default organization
  let org = await prisma.organization.findFirst({
    where: { ownerId: user.id }
  });

  if (!org) {
    org = await prisma.organization.create({
      data: {
        name: 'CYBERSPLOI Defense Mesh',
        description: 'Primary Enterprise SOC and Autonomous Pentesting Unit',
        ownerId: user.id
      }
    });
    console.log(`✅ Organization created: ${org.name} (${org.id})`);

    await prisma.user_Organization.create({
      data: {
        userId: user.id,
        organizationId: org.id,
        role: 'owner'
      }
    });
  } else {
    console.log(`✅ Organization exists: ${org.name} (${org.id})`);
  }

  // 3. Seed Assets
  const assetsData = [
    { type: 'api', value: 'https://api.cybersploi.io', description: 'Production API Gateway & Ingress' },
    { type: 'website', value: 'https://app.cybersploi.io', description: 'Main Operator Dashboard & Web UI' },
    { type: 'domain', value: 'mesh.cybersploi.io', description: 'Internal Microservice Service Mesh' },
    { type: 'ip', value: '198.51.100.42', description: 'Perimeter Edge Load Balancer' }
  ];

  const assets = [];
  for (const a of assetsData) {
    const asset = await prisma.asset.upsert({
      where: {
        organizationId_type_value: {
          organizationId: org.id,
          type: a.type,
          value: a.value
        }
      },
      update: { verificationStatus: 'verified' },
      create: {
        organizationId: org.id,
        type: a.type,
        value: a.value,
        description: a.description,
        verificationStatus: 'verified'
      }
    });
    assets.push(asset);
  }
  console.log(`✅ Seeded ${assets.length} production assets`);

  // 4. Seed Scans
  const primaryAsset = assets[0];
  const webAsset = assets[1];

  let scan1 = await prisma.scan.findFirst({
    where: { organizationId: org.id, assetId: primaryAsset.id }
  });

  if (!scan1) {
    scan1 = await prisma.scan.create({
      data: {
        organizationId: org.id,
        assetId: primaryAsset.id,
        type: 'full',
        status: 'completed',
        progress: 100,
        findings: 4,
        criticalCount: 2,
        highCount: 1,
        startedAt: new Date(Date.now() - 3600000 * 4),
        completedAt: new Date(Date.now() - 3600000 * 3)
      }
    });
    console.log(`✅ Seeded Scan 1: ${scan1.id}`);
  }

  let scan2 = await prisma.scan.findFirst({
    where: { organizationId: org.id, assetId: webAsset.id }
  });

  if (!scan2) {
    scan2 = await prisma.scan.create({
      data: {
        organizationId: org.id,
        assetId: webAsset.id,
        type: 'quick',
        status: 'running',
        progress: 74,
        findings: 2,
        criticalCount: 0,
        highCount: 1,
        startedAt: new Date(Date.now() - 1800000)
      }
    });
    console.log(`✅ Seeded Scan 2: ${scan2.id}`);
  }

  // 5. Seed Vulnerabilities
  const vulnsData = [
    {
      scanId: scan1.id,
      assetId: primaryAsset.id,
      title: 'Remote Code Execution in Apache Struts (CVE-2024-3891)',
      description: 'Improper input sanitization in OGNL processing allows unauthenticated remote code execution.',
      type: 'rce',
      severity: 'critical',
      cvss: '9.8',
      cve: 'CVE-2024-3891',
      cwe: 'CWE-94',
      status: 'open',
      remediation: 'Patch Apache Struts to v6.3.0.2 or deploy perimeter WAF inspection filter.'
    },
    {
      scanId: scan1.id,
      assetId: primaryAsset.id,
      title: 'SQL Injection in User Authentication (/api/v1/auth)',
      description: 'Unescaped user input in username query parameter allows database schema exfiltration and credential bypass.',
      type: 'sql_injection',
      severity: 'critical',
      cvss: '9.1',
      cve: 'CVE-2024-1234',
      cwe: 'CWE-89',
      status: 'open',
      remediation: 'Enforce parameterized prepared statements with Prisma ORM.'
    },
    {
      scanId: scan1.id,
      assetId: primaryAsset.id,
      title: 'Reflected Cross-Site Scripting (XSS) in Search Filter',
      description: 'Payload reflected in response body without HTML entity encoding or Content-Security-Policy enforcement.',
      type: 'xss',
      severity: 'high',
      cvss: '7.5',
      cve: 'CVE-2024-5231',
      cwe: 'CWE-79',
      status: 'open',
      remediation: 'Implement context-aware DOM sanitization with DOMPurify and strict CSP.'
    },
    {
      scanId: scan2.id,
      assetId: webAsset.id,
      title: 'Insecure Direct Object Reference (IDOR) on Tenant Assets',
      description: 'Missing tenant isolation check allows authenticated operators to view asset inventory across organizations.',
      type: 'auth_bypass',
      severity: 'high',
      cvss: '7.2',
      cve: 'CWE-639',
      cwe: 'CWE-639',
      status: 'remediated',
      remediation: 'Enforce tenant-level authorization filter on all database queries.'
    },
    {
      scanId: scan2.id,
      assetId: webAsset.id,
      title: 'TLS 1.0/1.1 Deprecated Cipher Suites Enabled',
      description: 'Legacy cryptographic ciphers (CBC mode, 3DES) supported on gateway perimeter.',
      type: 'crypto_flaw',
      severity: 'medium',
      cvss: '5.3',
      cve: 'CWE-326',
      cwe: 'CWE-326',
      status: 'open',
      remediation: 'Disable TLS < 1.2 and configure modern PFS cipher suites.'
    }
  ];

  for (const v of vulnsData) {
    const existing = await prisma.vulnerability.findFirst({
      where: { organizationId: org.id, title: v.title }
    });
    if (!existing) {
      await prisma.vulnerability.create({
        data: {
          organizationId: org.id,
          scanId: v.scanId,
          assetId: v.assetId,
          title: v.title,
          description: v.description,
          type: v.type,
          severity: v.severity,
          cvss: v.cvss,
          cve: v.cve,
          cwe: v.cwe,
          status: v.status,
          remediation: v.remediation
        }
      });
    }
  }
  console.log(`✅ Seeded ${vulnsData.length} vulnerabilities`);

  // 6. Seed Reports
  const report1 = await prisma.report.findFirst({
    where: { organizationId: org.id, title: 'Q3 2024 Red Team & Penetration Assessment' }
  });
  if (!report1) {
    await prisma.report.create({
      data: {
        organizationId: org.id,
        title: 'Q3 2024 Red Team & Penetration Assessment',
        description: 'Comprehensive offensive security evaluation of enterprise ingress and perimeter.',
        format: 'pdf',
        findings: 5,
        criticalCount: 2,
        highCount: 2
      }
    });
    console.log('✅ Seeded Executive Report');
  }

  console.log('🚀 Database seeding finished successfully!');
}

main()
  .catch((e) => {
    console.error('❌ Error seeding database:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
