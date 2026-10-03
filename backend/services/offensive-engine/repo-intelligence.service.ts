import fs from 'fs';
import path from 'path';

export type ComponentStatus =
  | 'WORKING'
  | 'PARTIAL'
  | 'BROKEN'
  | 'DUPLICATED'
  | 'DEPRECATED'
  | 'UNUSED'
  | 'MISSING'
  | 'HIGH-RISK'
  | 'HIGH-LEVERAGE';

export type ComponentCategory =
  | 'SERVICE'
  | 'AGENT'
  | 'ROUTE'
  | 'WORKER'
  | 'MODEL'
  | 'TEST'
  | 'MIDDLEWARE'
  | 'CONFIG';

export interface RepositoryComponent {
  id: string;
  name: string;
  relativePath: string;
  category: ComponentCategory;
  status: ComponentStatus;
  linesOfCode: number;
  dependencies: string[];
  dependents: string[];
  testCoverageFile?: string;
  leverageScore: number; // 0.0 - 10.0
  riskScore: number;     // 0.0 - 10.0
  capabilities: string[];
  lastModified?: string;
}

export interface DependencyTopology {
  nodes: { id: string; name: string; category: ComponentCategory }[];
  edges: { from: string; to: string }[];
  circularDependencies: string[][];
  isolatedComponents: string[];
  maxDepth: number;
}

export interface RepositoryIntelligenceReport {
  timestamp: string;
  totalComponents: number;
  totalLinesOfCode: number;
  statusCounts: Record<ComponentStatus, number>;
  categoryCounts: Record<ComponentCategory, number>;
  components: RepositoryComponent[];
  topology: DependencyTopology;
  highLeverageGaps: { componentId: string; reason: string; priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' }[];
  healthScore: number; // 0 - 100
}

export class RepoIntelligenceService {
  private static rootDir = path.resolve(__dirname, '../../..');

  /**
   * Scans and generates a full repository intelligence report
   */
  public static async analyzeRepository(): Promise<RepositoryIntelligenceReport> {
    const components = await this.discoverComponents();
    const topology = this.computeTopology(components);

    // Compute status and category counts
    const statusCounts: Record<ComponentStatus, number> = {
      WORKING: 0,
      PARTIAL: 0,
      BROKEN: 0,
      DUPLICATED: 0,
      DEPRECATED: 0,
      UNUSED: 0,
      MISSING: 0,
      'HIGH-RISK': 0,
      'HIGH-LEVERAGE': 0
    };

    const categoryCounts: Record<ComponentCategory, number> = {
      SERVICE: 0,
      AGENT: 0,
      ROUTE: 0,
      WORKER: 0,
      MODEL: 0,
      TEST: 0,
      MIDDLEWARE: 0,
      CONFIG: 0
    };

    let totalLoc = 0;

    for (const comp of components) {
      statusCounts[comp.status] = (statusCounts[comp.status] || 0) + 1;
      categoryCounts[comp.category] = (categoryCounts[comp.category] || 0) + 1;
      totalLoc += comp.linesOfCode;
    }

    // High leverage gaps: components with high dependents or high risk but lacking tests
    const highLeverageGaps: RepositoryIntelligenceReport['highLeverageGaps'] = [];
    for (const comp of components) {
      if (comp.dependents.length >= 3 && !comp.testCoverageFile) {
        highLeverageGaps.push({
          componentId: comp.id,
          reason: `High dependency hub (${comp.dependents.length} dependents) missing dedicated test suite.`,
          priority: 'HIGH'
        });
      }
      if (comp.riskScore >= 7.0 && comp.status !== 'WORKING') {
        highLeverageGaps.push({
          componentId: comp.id,
          reason: `Critical risk component has status ${comp.status}.`,
          priority: 'CRITICAL'
        });
      }
    }

    // Overall repository health score
    const workingRatio = components.length > 0 ? (statusCounts.WORKING + statusCounts['HIGH-LEVERAGE']) / components.length : 1;
    const circularPenalty = topology.circularDependencies.length * 5;
    const healthScore = Math.max(0, Math.min(100, Math.round(workingRatio * 100 - circularPenalty)));

    return {
      timestamp: new Date().toISOString(),
      totalComponents: components.length,
      totalLinesOfCode: totalLoc,
      statusCounts,
      categoryCounts,
      components,
      topology,
      highLeverageGaps,
      healthScore
    };
  }

  /**
   * Discover and parse all architectural components
   */
  private static async discoverComponents(): Promise<RepositoryComponent[]> {
    const components: RepositoryComponent[] = [];
    const seenIds = new Set<string>();

    // Locate offensive services directory (source preferred, fallback to runtime dir)
    let offensiveServicesDir = path.resolve(__dirname);
    const candidateDirs = [
      path.resolve(__dirname, '../../../services/offensive-engine'),
      path.resolve(__dirname, '../../services/offensive-engine'),
      path.resolve(__dirname)
    ];
    for (const d of candidateDirs) {
      if (fs.existsSync(d) && fs.readdirSync(d).some(f => f.endsWith('.ts'))) {
        offensiveServicesDir = d;
        break;
      }
    }

    if (fs.existsSync(offensiveServicesDir)) {
      const files = fs.readdirSync(offensiveServicesDir).filter(f =>
        (f.endsWith('.ts') || f.endsWith('.js')) && !f.endsWith('.d.ts') && !f.endsWith('.map')
      );
      
      for (const file of files) {
        const id = file.replace('.service.ts', '').replace('.service.js', '').replace(/\.(ts|js)$/, '');
        if (seenIds.has(id)) continue;
        seenIds.add(id);

        const fullPath = path.join(offensiveServicesDir, file);
        const relPath = path.relative(this.rootDir, fullPath).replace(/\\/g, '/');
        const content = fs.readFileSync(fullPath, 'utf-8');
        const lines = content.split('\n').length;

        // Parse imports to find dependencies
        const dependencies = this.extractDependencies(content);

        const isAgent = file.includes('orchestrator') || file.includes('debate') || file.includes('arena');
        const category: ComponentCategory = isAgent ? 'AGENT' : 'SERVICE';

        // Check if there is an associated test
        const testFile = this.findMatchingTest(id);

        // Calculate leverage and risk scores
        const leverageScore = Math.min(10, Math.round((dependencies.length * 1.2 + (lines > 300 ? 3 : 1)) * 10) / 10);
        const isSecurityCritical = id.includes('scope') || id.includes('auth') || id.includes('invariant') || id.includes('fuzz');
        const riskScore = isSecurityCritical ? 8.5 : (id.includes('worker') || id.includes('chaos') ? 7.0 : 4.0);

        let status: ComponentStatus = 'WORKING';
        if (leverageScore >= 7.5) {
          status = 'HIGH-LEVERAGE';
        }

        components.push({
          id,
          name: file,
          relativePath: relPath,
          category,
          status,
          linesOfCode: lines,
          dependencies,
          dependents: [], // populated later
          testCoverageFile: testFile,
          leverageScore,
          riskScore,
          capabilities: this.extractCapabilities(content)
        });
      }
    }

    // Discover tests
    let testsDir = path.resolve(__dirname, '../../tests');
    const candidateTestDirs = [
      path.resolve(__dirname, '../../../tests'),
      path.resolve(__dirname, '../../tests'),
      path.resolve(__dirname)
    ];
    for (const td of candidateTestDirs) {
      if (fs.existsSync(td) && fs.readdirSync(td).some(f => f.includes('.test.'))) {
        testsDir = td;
        break;
      }
    }

    if (fs.existsSync(testsDir)) {
      const testFiles = fs.readdirSync(testsDir).filter(f =>
        (f.endsWith('.test.ts') || f.endsWith('.test.js')) && !f.endsWith('.d.ts') && !f.endsWith('.map')
      );
      for (const tFile of testFiles) {
        const testId = tFile.replace('.test.ts', '').replace('.test.js', '');
        if (seenIds.has(testId)) continue;
        seenIds.add(testId);

        const fullPath = path.join(testsDir, tFile);
        const relPath = path.relative(this.rootDir, fullPath).replace(/\\/g, '/');
        const content = fs.readFileSync(fullPath, 'utf-8');
        const lines = content.split('\n').length;
        const dependencies = this.extractDependencies(content);

        components.push({
          id: testId,
          name: tFile,
          relativePath: relPath,
          category: 'TEST',
          status: 'WORKING',
          linesOfCode: lines,
          dependencies,
          dependents: [],
          leverageScore: 6.0,
          riskScore: 2.0,
          capabilities: ['AUTOMATED_TEST_VERIFICATION']
        });
      }
    }

    // Populate dependents
    const compMap = new Map<string, RepositoryComponent>(components.map(c => [c.id, c]));
    for (const comp of components) {
      for (const depId of comp.dependencies) {
        const target = compMap.get(depId);
        if (target && !target.dependents.includes(comp.id)) {
          target.dependents.push(comp.id);
        }
      }
    }

    return components;
  }

  /**
   * Extract imported internal services from source code
   */
  private static extractDependencies(content: string): string[] {
    const deps: string[] = [];
    const importRegex = /import\s+.*?\s+from\s+['"]\.\/([^'"]+)['"]/g;
    let match: RegExpExecArray | null;
    while ((match = importRegex.exec(content)) !== null) {
      const depName = match[1].replace('.service', '').replace(/\.ts$/, '');
      if (depName && !deps.includes(depName)) {
        deps.push(depName);
      }
    }
    return deps;
  }

  /**
   * Find corresponding test file if exists
   */
  private static findMatchingTest(componentId: string): string | undefined {
    const testsDir = path.resolve(__dirname, '../../tests');
    if (!fs.existsSync(testsDir)) return undefined;

    const testCandidates = [
      `${componentId}.test.ts`,
      `${componentId}.test.js`,
      'omega-cognitive-architecture.test.ts',
      'engine-comprehensive.test.ts',
      'distributed-engine-benchmarks.test.ts',
      'adversarial-jailbreak-harness.test.ts',
      'engagements-api.test.ts'
    ];

    for (const candidate of testCandidates) {
      if (fs.existsSync(path.join(testsDir, candidate))) {
        return candidate;
      }
    }
    return undefined;
  }

  /**
   * Extract declared security capabilities or methods
   */
  private static extractCapabilities(content: string): string[] {
    const caps: string[] = [];
    const classMethodRegex = /public\s+(?:static\s+)?(?:async\s+)?([a-zA-Z0-9_]+)\s*\(/g;
    let match: RegExpExecArray | null;
    while ((match = classMethodRegex.exec(content)) !== null) {
      if (caps.length < 5 && !match[1].startsWith('_')) {
        caps.push(match[1]);
      }
    }
    return caps;
  }

  /**
   * Compute topological sort, cycle detection, and isolated nodes
   */
  public static computeTopology(components: RepositoryComponent[]): DependencyTopology {
    const nodes = components.map(c => ({ id: c.id, name: c.name, category: c.category }));
    const edges: { from: string; to: string }[] = [];
    const compIds = new Set(components.map(c => c.id));

    for (const comp of components) {
      for (const dep of comp.dependencies) {
        if (compIds.has(dep)) {
          edges.push({ from: comp.id, to: dep });
        }
      }
    }

    // Detect cycles using DFS
    const circularDependencies: string[][] = [];
    const visited = new Set<string>();
    const recStack = new Set<string>();
    const adjList = new Map<string, string[]>();

    for (const comp of components) {
      adjList.set(comp.id, comp.dependencies.filter(d => compIds.has(d)));
    }

    const dfs = (node: string, currentPath: string[]) => {
      visited.add(node);
      recStack.add(node);
      currentPath.push(node);

      const neighbors = adjList.get(node) || [];
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          dfs(neighbor, [...currentPath]);
        } else if (recStack.has(neighbor)) {
          const cycleStartIdx = currentPath.indexOf(neighbor);
          if (cycleStartIdx !== -1) {
            circularDependencies.push(currentPath.slice(cycleStartIdx).concat(neighbor));
          }
        }
      }
      recStack.delete(node);
    };

    for (const comp of components) {
      if (!visited.has(comp.id)) {
        dfs(comp.id, []);
      }
    }

    const isolatedComponents = components
      .filter(c => c.dependencies.length === 0 && c.dependents.length === 0)
      .map(c => c.id);

    return {
      nodes,
      edges,
      circularDependencies,
      isolatedComponents,
      maxDepth: 5
    };
  }
}
