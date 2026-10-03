/**
 * Attack Graph & Adversary Chaining Engine
 * Synthesizes discovered assets, services, applications, and verified vulnerabilities
 * into a directed attack graph with evidence-backed edges and critical exploitation chains.
 */

class AttackGraphService {
  /**
   * Build complete Attack Graph nodes and edges from assessment findings
   */
  static generateAttackGraph({ host, dnsData, portData, tlsData, appData, verifiedFindings }) {
    const nodes = [];
    const edges = [];
    const nodeMap = new Set();

    const addNode = (node) => {
      if (!nodeMap.has(node.nodeId)) {
        nodeMap.add(node.nodeId);
        nodes.push(node);
      }
    };

    const addEdge = (edge) => {
      edges.push({
        ...edge,
        confidence: edge.confidence || 1.0,
        isCriticalPath: !!edge.isCriticalPath
      });
    };

    // 1. Root Target Node
    const targetNodeId = `target:${host}`;
    addNode({
      nodeId: targetNodeId,
      label: host,
      category: 'TARGET',
      severity: 'info',
      status: 'discovered',
      properties: JSON.stringify({ host, targetType: 'primary_assessment_target' })
    });

    // 2. Resolved Asset / IP Nodes
    if (dnsData?.records?.a) {
      dnsData.records.a.forEach((ip, idx) => {
        const ipNodeId = `ip:${ip}`;
        addNode({
          nodeId: ipNodeId,
          label: `IPv4: ${ip}`,
          category: 'ASSET',
          severity: 'info',
          status: 'discovered',
          properties: JSON.stringify({ ip, addressFamily: 'IPv4' })
        });
        addEdge({
          sourceNodeId: targetNodeId,
          targetNodeId: ipNodeId,
          relation: 'resolves_to',
          confidence: 1.0
        });
      });
    }

    // 3. Service Nodes (Open Ports)
    const openPorts = portData?.openPorts || [];
    openPorts.forEach((p) => {
      const serviceNodeId = `service:${host}:${p.port}`;
      const isSensitivePort = [21, 22, 23, 3306, 5432, 1433, 6379, 27017].includes(p.port);
      addNode({
        nodeId: serviceNodeId,
        label: `Port ${p.port} (${p.service})`,
        category: 'SERVICE',
        severity: isSensitivePort ? 'high' : 'info',
        status: isSensitivePort ? 'exposed' : 'active',
        properties: JSON.stringify({ port: p.port, service: p.service, banner: p.banner })
      });

      // Link Target -> Service
      addEdge({
        sourceNodeId: targetNodeId,
        targetNodeId: serviceNodeId,
        relation: 'exposes_service',
        confidence: 1.0
      });
    });

    // 4. Application / Gateway Node
    if (appData?.webServer || appData?.statusCode) {
      const appNodeId = `app:${host}`;
      addNode({
        nodeId: appNodeId,
        label: appData.webServer || 'HTTP Edge Gateway',
        category: 'APPLICATION',
        severity: 'info',
        status: 'active',
        properties: JSON.stringify({
          webServer: appData.webServer,
          statusCode: appData.statusCode,
          baseUrl: appData.baseUrl
        })
      });

      // Link Web Ports to Application
      openPorts.filter(p => [80, 443, 8080, 8443].includes(p.port)).forEach(p => {
        addEdge({
          sourceNodeId: `service:${host}:${p.port}`,
          targetNodeId: appNodeId,
          relation: 'hosts_application',
          confidence: 1.0
        });
      });

      // 5. Discovered Endpoints
      if (appData.discoveredEndpoints) {
        appData.discoveredEndpoints.forEach((ep) => {
          const epNodeId = `endpoint:${host}${ep.path}`;
          const isSensitive = ['exposed_environment_secrets', 'exposed_git_repository', 'spring_actuator_exposed', 'exposed_source_map', 'database_dump_leak', 'exposed_oauth_metadata'].includes(ep.type);
          addNode({
            nodeId: epNodeId,
            label: ep.path,
            category: 'ENDPOINT',
            severity: isSensitive ? 'critical' : 'medium',
            status: isSensitive ? 'compromised' : 'discovered',
            properties: JSON.stringify(ep)
          });
          addEdge({
            sourceNodeId: appNodeId,
            targetNodeId: epNodeId,
            relation: 'exposes_endpoint',
            confidence: 1.0,
            isCriticalPath: isSensitive
          });
        });
      }
    }

    // 6. Vulnerability Nodes & Chaining
    verifiedFindings.forEach((v, idx) => {
      const vulnNodeId = `vuln:${v.cve || idx}:${host}`;
      addNode({
        nodeId: vulnNodeId,
        label: v.title,
        category: 'VULNERABILITY',
        severity: v.severity.toLowerCase(),
        status: 'verified',
        properties: JSON.stringify({
          cvss: v.cvss,
          cwe: v.cwe,
          cve: v.cve,
          remediation: v.remediation
        })
      });

      // Connect Vulnerability to corresponding source node
      let sourceNode = targetNodeId;
      if (v.endpoint && v.endpoint.includes(':')) {
        const portPart = v.endpoint.split(':')[1];
        const matchingService = `service:${host}:${portPart}`;
        if (nodeMap.has(matchingService)) sourceNode = matchingService;
      } else if (v.endpoint && v.endpoint.includes('/')) {
        const matchingEp = `endpoint:${host}${v.endpoint.replace(/https?:\/\/[^/]+/, '')}`;
        if (nodeMap.has(matchingEp)) sourceNode = matchingEp;
        else if (nodeMap.has(`app:${host}`)) sourceNode = `app:${host}`;
      }

      addEdge({
        sourceNodeId: sourceNode,
        targetNodeId: vulnNodeId,
        relation: 'manifests_vulnerability',
        confidence: 0.98,
        isCriticalPath: v.severity === 'CRITICAL' || v.severity === 'HIGH'
      });

      // If high/critical, link to privilege / impact boundary
      if (v.severity === 'CRITICAL' || v.severity === 'HIGH') {
        const privNodeId = `privilege:${v.cve || idx}`;
        addNode({
          nodeId: privNodeId,
          label: v.title.includes('Administrative') ? 'Administrative Perimeter Access' : 'Sensitive Data Read Access',
          category: 'PRIVILEGE',
          severity: 'critical',
          status: 'reachable',
          properties: JSON.stringify({ impactLevel: 'high_blast_radius', privilegeEscalationPotential: true })
        });
        addEdge({
          sourceNodeId: vulnNodeId,
          targetNodeId: privNodeId,
          relation: 'enables_privilege',
          confidence: 0.95,
          isCriticalPath: true
        });
      }
    });

    return {
      nodes,
      edges,
      stats: {
        totalNodes: nodes.length,
        totalEdges: edges.length,
        criticalChains: edges.filter(e => e.isCriticalPath).length
      }
    };
  }
}

module.exports = AttackGraphService;
