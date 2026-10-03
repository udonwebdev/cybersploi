"use client";

import React, { useEffect, useRef } from "react";

interface CyberCoreSceneProps {
  scrollProgress: number; // 0 to 1
  mousePos: { x: number; y: number };
}

export const CyberCoreScene: React.FC<CyberCoreSceneProps> = ({
  scrollProgress,
  mousePos,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener("resize", handleResize);

    // Particle nodes for ambient space
    const PARTICLE_COUNT = 140;
    const particles = Array.from({ length: PARTICLE_COUNT }, () => ({
      x: (Math.random() - 0.5) * width * 1.6,
      y: (Math.random() - 0.5) * height * 1.6,
      z: Math.random() * 900 + 100,
      size: Math.random() * 2 + 1,
      speedZ: Math.random() * 0.4 + 0.1,
      hue: Math.random() > 0.8 ? 260 : 190, // cyan or subtle violet
    }));

    // Threat network nodes for Section 2
    const NETWORK_NODES = 42;
    const networkNodes = Array.from({ length: NETWORK_NODES }, (_, i) => ({
      x: (Math.cos((i / NETWORK_NODES) * Math.PI * 2) + (Math.random() - 0.5) * 0.3) * 320,
      y: (Math.sin((i / NETWORK_NODES) * Math.PI * 2) + (Math.random() - 0.5) * 0.3) * 220,
      z: (Math.random() - 0.5) * 400,
      baseColor: "#00d2ff",
      isCompromised: i % 4 === 0,
      pulse: Math.random() * Math.PI * 2,
    }));

    let baseRotation = 0;

    const render = () => {
      baseRotation += 0.004;

      // Clear dark infinite space with subtle depth gradient
      ctx.fillStyle = "#050609";
      ctx.fillRect(0, 0, width, height);

      // Subtle atmospheric radial glow
      const radialGradient = ctx.createRadialGradient(
        width / 2 + mousePos.x * 40,
        height / 2 + mousePos.y * 40,
        50,
        width / 2,
        height / 2,
        Math.max(width, height) * 0.85
      );
      radialGradient.addColorStop(0, "rgba(0, 180, 255, 0.06)");
      radialGradient.addColorStop(0.5, "rgba(139, 92, 246, 0.025)");
      radialGradient.addColorStop(1, "rgba(5, 6, 9, 0)");
      ctx.fillStyle = radialGradient;
      ctx.fillRect(0, 0, width, height);

      // Digital horizon grid
      ctx.save();
      ctx.strokeStyle = "rgba(0, 210, 255, 0.025)";
      ctx.lineWidth = 1;
      const gridSpacing = 48;
      for (let x = 0; x < width; x += gridSpacing) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSpacing) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }
      ctx.restore();

      // CAMERA & 3D PROJECTION MATH
      // Scroll shifts camera push-in and section states
      // Stage 0: 0-0.15 (Hero)
      // Stage 1: 0.15-0.35 (Threat Network)
      // Stage 2: 0.35-0.55 (Intelligence Sphere)
      // Stage 3: 0.55-0.75 (Horizontal Pipeline & Dashboard)
      // Stage 4: 0.75-1.0 (Enterprise Core / Shield)
      const p = scrollProgress;
      const fov = 420;
      const centerX = width / 2 + (p < 0.2 ? (width > 900 ? width * 0.18 : 0) : 0);
      const centerY = height / 2;

      // Project ambient particles in 3D
      particles.forEach((pt) => {
        pt.z -= pt.speedZ + p * 2.5;
        if (pt.z < 10) pt.z = 1000;

        const scale = fov / pt.z;
        const px = centerX + pt.x * scale + mousePos.x * 20;
        const py = centerY + pt.y * scale + mousePos.y * 20;

        if (px >= 0 && px <= width && py >= 0 && py <= height) {
          const alpha = Math.min(1, (1000 - pt.z) / 700) * 0.45;
          ctx.beginPath();
          ctx.arc(px, py, pt.size * scale, 0, Math.PI * 2);
          ctx.fillStyle =
            pt.hue === 260
              ? `rgba(168, 85, 247, ${alpha})`
              : `rgba(0, 210, 255, ${alpha})`;
          ctx.fill();
        }
      });

      // SECTION 2: THREAT NETWORK (Activates between 0.15 and 0.40)
      if (p >= 0.12 && p <= 0.45) {
        const netOpacity =
          p < 0.2
            ? (p - 0.12) / 0.08
            : p > 0.38
            ? (0.45 - p) / 0.07
            : 1;

        ctx.save();
        ctx.globalAlpha = Math.max(0, Math.min(1, netOpacity));

        const projectedNodes: { x: number; y: number; isCompromised: boolean; z: number }[] = [];

        networkNodes.forEach((node) => {
          node.pulse += 0.03;
          // 3D rotation
          const rotX = node.x * Math.cos(baseRotation * 0.6) - node.z * Math.sin(baseRotation * 0.6);
          const rotZ = node.x * Math.sin(baseRotation * 0.6) + node.z * Math.cos(baseRotation * 0.6) + 500;
          const scale = fov / rotZ;
          const px = centerX + rotX * scale;
          const py = centerY + node.y * scale;

          projectedNodes.push({ x: px, y: py, isCompromised: node.isCompromised, z: rotZ });

          // Draw node
          const compromisedProg = Math.min(1, Math.max(0, (p - 0.18) * 6));
          const nodeColor = node.isCompromised && compromisedProg > 0.3
            ? `rgba(255, 51, 102, ${0.4 + Math.sin(node.pulse) * 0.3})`
            : "rgba(0, 210, 255, 0.7)";

          ctx.beginPath();
          ctx.arc(px, py, 3.5 * scale, 0, Math.PI * 2);
          ctx.fillStyle = nodeColor;
          ctx.fill();
        });

        // Draw network connection lines
        ctx.lineWidth = 0.8;
        for (let i = 0; i < projectedNodes.length; i++) {
          for (let j = i + 1; j < projectedNodes.length; j++) {
            const dx = projectedNodes[i].x - projectedNodes[j].x;
            const dy = projectedNodes[i].y - projectedNodes[j].y;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < 110) {
              const alpha = (1 - dist / 110) * 0.35;
              ctx.strokeStyle =
                projectedNodes[i].isCompromised || projectedNodes[j].isCompromised
                  ? `rgba(255, 51, 102, ${alpha})`
                  : `rgba(0, 210, 255, ${alpha})`;
              ctx.beginPath();
              ctx.moveTo(projectedNodes[i].x, projectedNodes[i].y);
              ctx.lineTo(projectedNodes[j].x, projectedNodes[j].y);
              ctx.stroke();
            }
          }
        }
        ctx.restore();
      }

      // SECTION 1, 3, 4, 8: CENTRAL 3D CYBERSECURITY CORE
      // The Core is a multilayered rotating crystalline/metallic structure
      // Layers:
      // 1. Outer Hexagonal Shield Ring
      // 2. Middle Gimbal Orbit Ring
      // 3. Inner Quantum Geodesic Core
      // 4. Central Pulsing Singularity Node
      ctx.save();
      const coreScale = 1 + (p < 0.2 ? p * 2.8 : p > 0.8 ? (1 - p) * 1.5 : 0.8);
      const rotY = baseRotation + mousePos.x * 0.4;
      const rotX = Math.sin(baseRotation * 0.5) * 0.3 + mousePos.y * 0.3;

      // Layer 1: Outer Hexagonal Shield Ring
      const hexRadius = 140 * coreScale;
      const hexPoints = 6;
      ctx.beginPath();
      for (let i = 0; i <= hexPoints; i++) {
        const angle = (i / hexPoints) * Math.PI * 2 + rotY * 0.5;
        const x3d = Math.cos(angle) * hexRadius;
        const y3d = Math.sin(angle) * hexRadius;
        const z3d = Math.sin(angle * 2 + baseRotation) * 40;

        // Rotate in 3D
        const rx = x3d;
        const ry = y3d * Math.cos(rotX) - z3d * Math.sin(rotX);
        const rz = y3d * Math.sin(rotX) + z3d * Math.cos(rotX) + 400;

        const scale = fov / rz;
        const px = centerX + rx * scale;
        const py = centerY + ry * scale;

        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.strokeStyle = "rgba(0, 210, 255, 0.4)";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Layer 2: Metallic Orbital Rings (3 orthogonal rings)
      const ringRadii = [115, 95, 75];
      ringRadii.forEach((radius, idx) => {
        const ringScale = radius * coreScale;
        const points = 32;
        ctx.beginPath();
        for (let i = 0; i <= points; i++) {
          const theta = (i / points) * Math.PI * 2;
          let x = Math.cos(theta) * ringScale;
          let y = Math.sin(theta) * ringScale;
          let z = 0;

          // Orient rings orthogonally
          if (idx === 1) {
            const temp = y;
            y = z;
            z = temp;
          } else if (idx === 2) {
            const temp = x;
            x = z;
            z = temp;
          }

          // Apply core rotation
          const cosY = Math.cos(rotY * (idx % 2 === 0 ? 1 : -1));
          const sinY = Math.sin(rotY * (idx % 2 === 0 ? 1 : -1));
          const rx = x * cosY - z * sinY;
          const rz = (x * sinY + z * cosY) * Math.cos(rotX) - y * Math.sin(rotX) + 400;
          const ry = (x * sinY + z * cosY) * Math.sin(rotX) + y * Math.cos(rotX);

          const scale = fov / rz;
          const px = centerX + rx * scale;
          const py = centerY + ry * scale;

          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
        ctx.strokeStyle =
          idx === 0
            ? "rgba(0, 210, 255, 0.55)"
            : idx === 1
            ? "rgba(56, 189, 248, 0.45)"
            : "rgba(168, 85, 247, 0.35)";
        ctx.lineWidth = idx === 0 ? 1.5 : 1;
        ctx.stroke();
      });

      // Layer 3: Central Crystalline Geodesic Icosahedron Nodes
      const nodeCount = 12;
      const innerRadius = 50 * coreScale;
      for (let i = 0; i < nodeCount; i++) {
        const phi = Math.acos(-1 + (2 * i) / nodeCount);
        const theta = Math.sqrt(nodeCount * Math.PI) * phi + rotY * 1.5;

        const x = innerRadius * Math.sin(phi) * Math.cos(theta);
        const y = innerRadius * Math.sin(phi) * Math.sin(theta);
        const z = innerRadius * Math.cos(phi);

        const rz = z * Math.cos(rotX) - y * Math.sin(rotX) + 400;
        const ry = z * Math.sin(rotX) + y * Math.cos(rotX);
        const rx = x;

        const scale = fov / rz;
        const px = centerX + rx * scale;
        const py = centerY + ry * scale;

        ctx.beginPath();
        ctx.arc(px, py, 2.5 * scale, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0, 245, 155, 0.85)";
        ctx.fill();

        // Connect node to center
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(px, py);
        ctx.strokeStyle = "rgba(0, 210, 255, 0.15)";
        ctx.lineWidth = 0.7;
        ctx.stroke();
      }

      // Central Pulsing Core
      const corePulse = Math.sin(baseRotation * 4) * 4;
      const coreGrad = ctx.createRadialGradient(
        centerX,
        centerY,
        0,
        centerX,
        centerY,
        (22 + corePulse) * coreScale
      );
      coreGrad.addColorStop(0, "rgba(255, 255, 255, 0.95)");
      coreGrad.addColorStop(0.2, "rgba(0, 210, 255, 0.8)");
      coreGrad.addColorStop(0.6, "rgba(0, 128, 255, 0.4)");
      coreGrad.addColorStop(1, "rgba(0, 0, 0, 0)");

      ctx.fillStyle = coreGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, (24 + corePulse) * coreScale, 0, Math.PI * 2);
      ctx.fill();

      ctx.restore();

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", handleResize);
    };
  }, [scrollProgress, mousePos]);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-0 block w-full h-full"
    />
  );
};
