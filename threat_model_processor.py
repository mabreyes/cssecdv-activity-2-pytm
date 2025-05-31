#!/usr/bin/env python3
"""
Threat Model Processor Module

This module handles the processing and output generation for threat models.
It includes functionality for:
- Threat analysis using pytm
- Command line argument processing
- Output generation (DFD, sequence diagrams, reports, JSON)
- Debug information and model configuration

Author: Generated using OWASP pytm
"""

import argparse
import sys
import json
from typing import Any
from datetime import datetime

from pytm import TM


class ThreatAnalyzer:
    """Analyzes and processes threats in the model."""
    
    @staticmethod
    def analyze_threats(threat_model: TM) -> None:
        """Analyze threats using pytm's built-in capabilities."""
        # pytm automatically identifies threats based on:
        # - Element types (Server, Datastore, ExternalEntity, Actor)
        # - Security properties (isSQL, isEncrypted, implementsAuthenticationScheme)
        # - Data flows and their protocols
        # - Trust boundaries and data classifications
        threat_model.process()


class ThreatModelProcessor:
    """Processes threat model based on command line arguments."""
    
    def __init__(self, threat_model: TM) -> None:
        """Initialize processor."""
        self.threat_model = threat_model
    
    def configure_model(self, args: argparse.Namespace) -> None:
        """Configure threat model based on arguments."""
        if args.sqldump:
            self.threat_model.sqlDump = args.sqldump
        
        if args.exclude:
            self.threat_model._threatsExcluded = args.exclude.split(',')
        
        if args.levels:
            for element in self.threat_model._elements:
                element.levels = set(args.levels)
    
    def process_output(self, args: argparse.Namespace) -> None:
        """Process output based on arguments."""
        if args.debug:
            self._print_debug_info()
        
        if args.stale_days:
            print(f"Stale days check: {args.stale_days} (not implemented in this model)")
        
        # Process the threat model
        ThreatAnalyzer.analyze_threats(self.threat_model)
        
        # Handle output arguments
        if args.dfd:
            output = self.threat_model.dfd(colormap=args.colormap)
            print(output)
            return
        
        if args.seq:
            print(self.threat_model.seq())
            return
        
        if args.report:
            print(self.threat_model.report(args.report))
            return
        
        if args.json:
            self._export_json(args.json)
            return
        
        # Default behavior
        if len(sys.argv) == 1:
            self._print_default_info()
    
    def _print_debug_info(self) -> None:
        """Print debug information."""
        print("Debug mode enabled")
        print(f"Elements: {len(self.threat_model._elements)}")
        print(f"Dataflows: {len(self.threat_model._flows)}")
        print(f"Boundaries: {len(self.threat_model._boundaries)}")
    
    def _make_json_safe(self, obj: Any) -> Any:
        """Convert object to JSON-serializable format."""
        if obj is None:
            return None
        elif isinstance(obj, (str, int, float, bool)):
            return obj
        elif isinstance(obj, (list, tuple)):
            return [self._make_json_safe(item) for item in obj]
        elif isinstance(obj, dict):
            return {str(k): self._make_json_safe(v) for k, v in obj.items()}
        elif hasattr(obj, '__dict__'):
            return str(obj)
        else:
            return str(obj)
    
    def _export_json(self, filename: str) -> None:
        """Export threat model to JSON."""
        try:
            # Custom JSON export to avoid pytm resolve() bug
            threat_model_data = {
                "metadata": {
                    "name": self.threat_model.name,
                    "description": self.threat_model.description,
                    "generated_at": datetime.now().isoformat(),
                    "pytm_version": "1.3.1",
                    "model_version": "1.0.0"
                },
                "boundaries": [],
                "elements": [],
                "dataflows": [],
                "threats": [],
                "findings": []
            }
            
            # Extract boundaries
            for boundary in self.threat_model._boundaries:
                threat_model_data["boundaries"].append({
                    "name": boundary.name,
                    "description": getattr(boundary, 'description', ''),
                    "type": "Boundary"
                })
            
            # Extract elements (actors, servers, datastores, etc.)
            for element in self.threat_model._elements:
                element_data = {
                    "name": element.name,
                    "type": element.__class__.__name__,
                    "description": getattr(element, 'description', ''),
                    "boundary": getattr(element.inBoundary, 'name', '') if hasattr(element, 'inBoundary') and element.inBoundary else '',
                    "properties": {}
                }
                
                # Add element-specific properties
                if hasattr(element, 'OS'):
                    element_data["properties"]["OS"] = element.OS
                if hasattr(element, 'isHardened'):
                    element_data["properties"]["isHardened"] = element.isHardened
                if hasattr(element, 'implementsAuthenticationScheme'):
                    element_data["properties"]["implementsAuthenticationScheme"] = element.implementsAuthenticationScheme
                if hasattr(element, 'sanitizesInput'):
                    element_data["properties"]["sanitizesInput"] = element.sanitizesInput
                if hasattr(element, 'validatesInput'):
                    element_data["properties"]["validatesInput"] = element.validatesInput
                if hasattr(element, 'isSQL'):
                    element_data["properties"]["isSQL"] = element.isSQL
                if hasattr(element, 'isEncrypted'):
                    element_data["properties"]["isEncrypted"] = element.isEncrypted
                if hasattr(element, 'isAdmin'):
                    element_data["properties"]["isAdmin"] = element.isAdmin
                
                threat_model_data["elements"].append(element_data)
            
            # Extract dataflows
            for flow in self.threat_model._flows:
                flow_data = {
                    "name": flow.name,
                    "source": flow.source.name if hasattr(flow.source, 'name') else str(flow.source),
                    "destination": flow.sink.name if hasattr(flow.sink, 'name') else str(flow.sink),
                    "protocol": getattr(flow, 'protocol', ''),
                    "port": getattr(flow, 'dstPort', ''),
                    "data": {},
                    "note": getattr(flow, 'note', '')
                }
                
                # Handle data object safely
                if flow.data:
                    if hasattr(flow.data, 'name'):
                        flow_data["data"]["name"] = flow.data.name
                    elif hasattr(flow.data, '__class__'):
                        flow_data["data"]["name"] = flow.data.__class__.__name__
                    else:
                        flow_data["data"]["name"] = str(flow.data)
                    
                    flow_data["data"]["classification"] = str(getattr(flow.data, 'classification', ''))
                    flow_data["data"]["isPII"] = getattr(flow.data, 'isPII', False)
                    flow_data["data"]["isCredentials"] = getattr(flow.data, 'isCredentials', False)
                    flow_data["data"]["isStored"] = getattr(flow.data, 'isStored', False)
                    flow_data["data"]["description"] = getattr(flow.data, 'description', '')
                
                threat_model_data["dataflows"].append(flow_data)
            
            # Initialize threats database without processing (to avoid the bug)
            try:
                self.threat_model._init_threats()
                
                # Extract threat definitions from pytm's threat database
                if hasattr(self.threat_model, '_threats') and self.threat_model._threats:
                    for threat in self.threat_model._threats:
                        threat_data = {
                            "id": self._make_json_safe(getattr(threat, 'id', '')),
                            "description": self._make_json_safe(getattr(threat, 'description', '')),
                            "details": self._make_json_safe(getattr(threat, 'details', '')),
                            "severity": self._make_json_safe(getattr(threat, 'severity', '')),
                            "stride": self._make_json_safe(getattr(threat, 'stride', '')),
                            "condition": self._make_json_safe(getattr(threat, 'condition', '')),
                            "target": self._make_json_safe(getattr(threat, 'target', '')),
                            "mitigations": self._make_json_safe(getattr(threat, 'mitigations', []))
                        }
                        threat_model_data["threats"].append(threat_data)
                
                # Try to get findings if they exist (without calling process)
                if hasattr(self.threat_model, '_findings') and self.threat_model._findings:
                    for finding in self.threat_model._findings:
                        finding_data = {
                            "id": self._make_json_safe(getattr(finding, 'id', '')),
                            "title": self._make_json_safe(getattr(finding, 'title', '')),
                            "description": self._make_json_safe(getattr(finding, 'description', '')),
                            "details": self._make_json_safe(getattr(finding, 'details', '')),
                            "severity": self._make_json_safe(getattr(finding, 'severity', '')),
                            "target": self._make_json_safe(getattr(finding, 'target', '')),
                            "type": self._make_json_safe(getattr(finding, 'type', '')),
                            "stride": self._make_json_safe(getattr(finding, 'stride', '')),
                            "condition": self._make_json_safe(getattr(finding, 'condition', '')),
                            "prerequisite": self._make_json_safe(getattr(finding, 'prerequisite', '')),
                            "mitigations": self._make_json_safe(getattr(finding, 'mitigations', []))
                        }
                        threat_model_data["findings"].append(finding_data)
                    
            except Exception as threat_error:
                print(f"Warning: Could not extract threat data: {threat_error}")
                # Continue with basic model data even if threat extraction fails
            
            # Add summary statistics
            threat_model_data["summary"] = {
                "total_boundaries": len(threat_model_data["boundaries"]),
                "total_elements": len(threat_model_data["elements"]),
                "total_dataflows": len(threat_model_data["dataflows"]),
                "total_threats": len(threat_model_data["threats"]),
                "total_findings": len(threat_model_data["findings"]),
                "elements_by_type": {},
                "findings_by_severity": {}
            }
            
            # Count elements by type
            for element in threat_model_data["elements"]:
                element_type = element["type"]
                threat_model_data["summary"]["elements_by_type"][element_type] = \
                    threat_model_data["summary"]["elements_by_type"].get(element_type, 0) + 1
            
            # Count findings by severity
            for finding in threat_model_data["findings"]:
                severity = finding.get("severity", "Unknown")
                threat_model_data["summary"]["findings_by_severity"][severity] = \
                    threat_model_data["summary"]["findings_by_severity"].get(severity, 0) + 1
            
            # Write to file with proper formatting
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(threat_model_data, f, indent=2, ensure_ascii=False)
            
            print(f"JSON output written to {filename}")
            print(f"Summary: {threat_model_data['summary']['total_elements']} elements, "
                  f"{threat_model_data['summary']['total_dataflows']} dataflows, "
                  f"{threat_model_data['summary']['total_findings']} findings")
            
        except Exception as e:
            print(f"Error writing JSON file: {e}")
            import traceback
            traceback.print_exc()
    
    def _print_default_info(self) -> None:
        """Print default information."""
        print("Building Web-based User Feedback System Threat Model...")
        print("Threat model processing complete!")
        print(f"Model: {self.threat_model.name}")
        print(f"Description: {self.threat_model.description}")
        print("\nUse --help to see available options") 