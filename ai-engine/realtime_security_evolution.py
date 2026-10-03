"""
Real-Time Security Evolution System
Runs continuous security evolution cycles every second
Integrates threat intelligence with agent evolution
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
import logging
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class EvolutionCycleMetrics:
    cycle_number: int
    threats_detected: int
    critical_threats: int
    agents_updated: int
    new_capabilities: int
    security_score: float
    average_adaptation: float
    timestamp: str

class RealtimeSecurityEvolutionSystem:
    def __init__(self, threat_scraper, agent_evolution_engine):
        self.threat_scraper = threat_scraper
        self.agent_evolution = agent_evolution_engine
        self.cycle_number = 0
        self.is_running = False
        self.cycle_history = []
        self.security_metrics = {
            'total_threats_detected': 0,
            'total_evolutions': 0,
            'system_uptime': datetime.now(),
            'average_cycle_time': 0,
            'security_score': 0.5
        }
        self.threat_cache = {}
        self.evolution_cache = {}
        
    async def start_evolution_loop(self, interval_seconds: float = 30.0):
        """Start continuous security evolution loop"""
        self.is_running = True
        logger.info("🚀 Starting Real-Time Security Evolution System")
        logger.info(f"📊 Evolution cycles will run every {interval_seconds} second(s)")
        
        try:
            while self.is_running:
                start_time = datetime.now()
                
                # Run one complete evolution cycle
                cycle_result = await self.run_evolution_cycle()
                
                # Calculate cycle metrics
                cycle_time = (datetime.now() - start_time).total_seconds()
                
                # Log cycle summary
                self.log_cycle_summary(cycle_result, cycle_time)
                
                # Wait for next cycle
                wait_time = max(0, interval_seconds - cycle_time)
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                else:
                    logger.warning(f"⚠️ Cycle took {cycle_time}s (exceeded interval {interval_seconds}s)")
                    
        except Exception as e:
            logger.error(f"❌ Evolution loop error: {e}")
            self.is_running = False
    
    async def run_evolution_cycle(self) -> Dict[str, Any]:
        """Run single evolution cycle (threat detection + agent evolution)"""
        self.cycle_number += 1
        cycle_start = datetime.now()
        
        cycle_data = {
            'cycle_number': self.cycle_number,
            'timestamp': cycle_start.isoformat(),
            'phases': {}
        }
        
        try:
            # Phase 1: Threat Intelligence Gathering
            phase1_start = datetime.now()
            threats = await self.threat_scraper.scrape_all_sources()
            phase1_time = (datetime.now() - phase1_start).total_seconds()
            
            threat_summary = self.threat_scraper.get_threat_summary(threats)
            cycle_data['phases']['threat_collection'] = {
                'duration': phase1_time,
                'threats_detected': threat_summary['total_threats_detected'],
                'critical_threats': threat_summary['critical_threats'],
                'sources_updated': threat_summary['sources_monitored']
            }
            
            self.security_metrics['total_threats_detected'] += threat_summary['total_threats_detected']
            
            # Phase 2: Threat Pattern Analysis
            phase2_start = datetime.now()
            patterns = await self.threat_scraper.identify_emerging_patterns(threats)
            phase2_time = (datetime.now() - phase2_start).total_seconds()
            
            cycle_data['phases']['pattern_analysis'] = {
                'duration': phase2_time,
                'patterns_identified': len(patterns),
                'pattern_types': [p['pattern_type'] for p in patterns]
            }
            
            # Phase 3: Agent Evolution
            phase3_start = datetime.now()
            all_threats_flat = []
            for source_threats in threats.values():
                all_threats_flat.extend(source_threats)
            
            evolution_result = await self.agent_evolution.evolve_agents(all_threats_flat)
            phase3_time = (datetime.now() - phase3_start).total_seconds()
            
            cycle_data['phases']['agent_evolution'] = {
                'duration': phase3_time,
                'agents_evolved': len(evolution_result['agents_evolved']),
                'total_new_capabilities': sum(len(v) for v in evolution_result['new_capabilities_acquired'].values())
            }
            
            self.security_metrics['total_evolutions'] += 1
            
            # Phase 4: Security Update Propagation
            phase4_start = datetime.now()
            security_updates = await self.agent_evolution.security_evolution_cycle(all_threats_flat)
            phase4_time = (datetime.now() - phase4_start).total_seconds()
            
            cycle_data['phases']['security_update_propagation'] = {
                'duration': phase4_time,
                'updates_triggered': len(security_updates['security_updates']),
                'patch_recommendations': len(security_updates['patch_recommendations'])
            }
            
            # Phase 5: System Health Check
            phase5_start = datetime.now()
            health_status = self.check_system_health(threat_summary, evolution_result)
            phase5_time = (datetime.now() - phase5_start).total_seconds()
            
            cycle_data['phases']['health_check'] = {
                'duration': phase5_time,
                'system_status': health_status['status'],
                'security_score': health_status['security_score']
            }
            
            # Calculate cycle metrics
            total_cycle_time = (datetime.now() - cycle_start).total_seconds()
            cycle_metrics = EvolutionCycleMetrics(
                cycle_number=self.cycle_number,
                threats_detected=threat_summary['total_threats_detected'],
                critical_threats=threat_summary['critical_threats'],
                agents_updated=len(evolution_result['agents_evolved']),
                new_capabilities=cycle_data['phases']['agent_evolution']['total_new_capabilities'],
                security_score=health_status['security_score'],
                average_adaptation=sum(a['adaptation_score'] for a in evolution_result['agents_evolved'].values()) / len(evolution_result['agents_evolved']),
                timestamp=datetime.now().isoformat()
            )
            
            cycle_data['metrics'] = asdict(cycle_metrics)
            cycle_data['total_cycle_time'] = total_cycle_time
            
            # Cache for quick access
            self.cycle_history.append(cycle_data)
            if len(self.cycle_history) > 1000:  # Keep last 1000 cycles
                self.cycle_history = self.cycle_history[-1000:]
            
            return cycle_data
            
        except Exception as e:
            logger.error(f"Evolution cycle error: {e}")
            return cycle_data
    
    def check_system_health(self, threat_summary: Dict, evolution_result: Dict) -> Dict[str, Any]:
        """Check overall system health"""
        health = {
            'status': 'HEALTHY',
            'security_score': 0.5,
            'issues': []
        }
        
        # Calculate security score based on threat response
        critical_threats = threat_summary['critical_threats']
        total_threats = threat_summary['total_threats_detected']
        agents_adapted = sum(1 for a in evolution_result['agents_evolved'].values() if a['adaptation_score'] > 0.6)
        avg_adaptation = sum(a['adaptation_score'] for a in evolution_result['agents_evolved'].values()) / len(evolution_result['agents_evolved'])
        
        # Security score formula
        threat_response = agents_adapted / len(evolution_result['agents_evolved']) if evolution_result['agents_evolved'] else 0
        adaptation_factor = avg_adaptation
        security_score = (threat_response * 0.6 + adaptation_factor * 0.4)
        
        health['security_score'] = min(security_score, 1.0)
        
        if critical_threats > 20:
            health['status'] = 'CRITICAL'
            health['issues'].append('HIGH_NUMBER_CRITICAL_THREATS')
        elif critical_threats > 10:
            health['status'] = 'WARNING'
            health['issues'].append('ELEVATED_CRITICAL_THREATS')
        elif avg_adaptation < 0.5:
            health['status'] = 'WARNING'
            health['issues'].append('LOW_AGENT_ADAPTATION')
        
        self.security_metrics['security_score'] = health['security_score']
        
        return health
    
    def log_cycle_summary(self, cycle_data: Dict[str, Any], cycle_time: float):
        """Log summary of evolution cycle"""
        metrics = cycle_data.get('metrics', {})
        
        status_symbol = {
            'cycle_number': f"Cycle #{metrics.get('cycle_number', '?')}",
            'threats': f"🔴 Threats: {metrics.get('threats_detected', 0)} ({metrics.get('critical_threats', 0)} critical)",
            'agents': f"🤖 Agents: {metrics.get('agents_updated', 0)} evolved",
            'capabilities': f"⚡ Capabilities: +{metrics.get('new_capabilities', 0)}",
            'security': f"🔐 Score: {metrics.get('security_score', 0):.2%}",
            'time': f"⏱️ {cycle_time:.3f}s"
        }
        
        log_msg = f"[{status_symbol['cycle_number']}] {status_symbol['threats']} | {status_symbol['agents']} | {status_symbol['capabilities']} | {status_symbol['security']} | {status_symbol['time']}"
        logger.info(log_msg)
    
    async def get_real_time_dashboard(self) -> Dict[str, Any]:
        """Get real-time dashboard data"""
        uptime = datetime.now() - self.security_metrics['system_uptime']
        
        dashboard = {
            'system_status': 'RUNNING' if self.is_running else 'STOPPED',
            'uptime_seconds': uptime.total_seconds(),
            'cycles_completed': self.cycle_number,
            'total_threats_detected': self.security_metrics['total_threats_detected'],
            'total_evolutions': self.security_metrics['total_evolutions'],
            'current_security_score': self.security_metrics['security_score'],
            'agent_status': self.agent_evolution.get_agent_status(),
            'recent_cycles': self.cycle_history[-10:] if self.cycle_history else [],
            'timestamp': datetime.now().isoformat()
        }
        
        return dashboard
    
    async def get_threat_timeline(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Get threat timeline for specified period"""
        timeline = []
        cutoff = datetime.now() - timedelta(hours=hours)
        
        for cycle in self.cycle_history:
            cycle_time = datetime.fromisoformat(cycle.get('timestamp', datetime.now().isoformat()))
            if cycle_time >= cutoff:
                timeline.append({
                    'cycle': cycle['cycle_number'],
                    'timestamp': cycle['timestamp'],
                    'threats_detected': cycle['phases']['threat_collection']['threats_detected'],
                    'critical_threats': cycle['phases']['threat_collection']['critical_threats'],
                    'security_score': cycle['metrics']['security_score']
                })
        
        return timeline
    
    async def get_agent_evolution_report(self) -> Dict[str, Any]:
        """Get comprehensive agent evolution report"""
        report = {
            'generation': self.agent_evolution.generation_number,
            'timestamp': datetime.now().isoformat(),
            'agent_details': {},
            'evolution_metrics': {}
        }
        
        for agent_type, agent_config in self.agent_evolution.agents.items():
            report['agent_details'][agent_type.value] = {
                'name': agent_config['name'],
                'total_capabilities': len(agent_config['capabilities']),
                'threat_knowledge_entries': len(agent_config['threat_knowledge']),
                'adaptation_score': agent_config['adaptation_score'],
                'recent_capabilities': agent_config['capabilities'][-10:],
                'generation_created': agent_config.get('generation_created', 1)
            }
        
        # Aggregate evolution metrics
        if self.agent_evolution.evolution_history:
            latest_evolution = self.agent_evolution.evolution_history[-1]
            report['evolution_metrics'] = {
                'latest_generation': latest_evolution['generation'],
                'agents_evolved': len(latest_evolution['agents_evolved']),
                'total_new_capabilities': sum(len(v) for v in latest_evolution['new_capabilities_acquired'].values()),
                'threats_analyzed': sum(latest_evolution['threat_adaptations'].values())
            }
        
        return report
    
    def stop_evolution_loop(self):
        """Stop the evolution loop"""
        self.is_running = False
        logger.info("🛑 Evolution loop stopped")
    
    async def get_system_statistics(self) -> Dict[str, Any]:
        """Get comprehensive system statistics"""
        uptime = datetime.now() - self.security_metrics['system_uptime']
        
        stats = {
            'system_metrics': {
                'uptime_seconds': uptime.total_seconds(),
                'cycles_completed': self.cycle_number,
                'current_status': 'RUNNING' if self.is_running else 'STOPPED',
                'timestamp': datetime.now().isoformat()
            },
            'threat_metrics': {
                'total_threats_detected': self.security_metrics['total_threats_detected'],
                'average_threats_per_cycle': self.security_metrics['total_threats_detected'] / max(1, self.cycle_number),
                'threat_sources_monitored': 8
            },
            'evolution_metrics': {
                'total_evolutions': self.security_metrics['total_evolutions'],
                'agents_active': len(self.agent_evolution.agents),
                'current_generation': self.agent_evolution.generation_number,
                'total_threat_knowledge': sum(len(a['threat_knowledge']) for a in self.agent_evolution.agents.values())
            },
            'security_metrics': {
                'current_security_score': self.security_metrics['security_score'],
                'average_agent_adaptation': sum(a['adaptation_score'] for a in self.agent_evolution.agents.values()) / len(self.agent_evolution.agents) if self.agent_evolution.agents else 0
            }
        }
        
        return stats
