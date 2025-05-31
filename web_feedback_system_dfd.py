#!/usr/bin/env python3
"""
Activity 2 - Threat Model - Data Flow Diagram - Web-based User Feedback System

This module defines a threat model for a web-based user feedback system
based on the DFD shown in the provided image. The system includes:
- User registration and authentication
- Feedback submission and storage
- Integration with LDAP and Authorization Provider

Author: Generated using OWASP pytm
"""

import argparse
import sys
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from pytm import (
    TM, Actor, Server, Datastore, Dataflow, Boundary, 
    Data, Classification, ExternalEntity
)
from pytm.pytm import _describe_classes, _list_elements


class SecurityProtocol(Enum):
    """Enumeration of security protocols used in the system."""
    HTTPS = "HTTPS"
    LDAPS = "LDAPS"
    TLS = "TLS"


class NetworkPort(Enum):
    """Enumeration of network ports used in the system."""
    HTTPS = 443
    LDAPS = 636
    MYSQL = 3306


@dataclass
class ComponentConfig:
    """Configuration for system components."""
    name: str
    description: str
    os: str = "Linux"
    is_hardened: bool = True
    implements_auth: bool = False
    sanitizes_input: bool = False
    validates_input: bool = False
    is_sql: bool = False
    is_encrypted: bool = False


@dataclass
class DataConfig:
    """Configuration for data objects."""
    name: str
    description: str
    classification: Classification
    is_pii: bool = False
    is_credentials: bool = False
    is_stored: bool = False


@dataclass
class DataflowConfig:
    """Configuration for data flows."""
    name: str
    protocol: SecurityProtocol
    port: NetworkPort
    note: Optional[str] = None


class BoundaryManager:
    """Manages trust boundaries for the threat model."""
    
    def __init__(self) -> None:
        """Initialize boundary manager with predefined boundaries."""
        self._boundaries = self._create_boundaries()
    
    def _create_boundaries(self) -> Dict[str, Boundary]:
        """Create and return trust boundaries."""
        return {
            'internet': Boundary("Internet"),
            'dmz': Boundary("DMZ"),
            'internal': Boundary("Internal Network")
        }
    
    def get_boundary(self, name: str) -> Boundary:
        """Get boundary by name."""
        if name not in self._boundaries:
            raise ValueError(f"Unknown boundary: {name}")
        return self._boundaries[name]
    
    @property
    def internet(self) -> Boundary:
        """Get Internet boundary."""
        return self._boundaries['internet']
    
    @property
    def dmz(self) -> Boundary:
        """Get DMZ boundary."""
        return self._boundaries['dmz']
    
    @property
    def internal(self) -> Boundary:
        """Get Internal Network boundary."""
        return self._boundaries['internal']


class ComponentFactory:
    """Factory for creating system components."""
    
    def __init__(self, boundary_manager: BoundaryManager) -> None:
        """Initialize component factory."""
        self.boundary_manager = boundary_manager
    
    def create_actor(self, config: ComponentConfig, boundary_name: str) -> Actor:
        """Create an Actor component."""
        actor = Actor(config.name)
        actor.description = config.description
        actor.inBoundary = self.boundary_manager.get_boundary(boundary_name)
        actor.isAdmin = False
        return actor
    
    def create_server(self, config: ComponentConfig, boundary_name: str) -> Server:
        """Create a Server component."""
        server = Server(config.name)
        server.description = config.description
        server.OS = config.os
        server.isHardened = config.is_hardened
        server.inBoundary = self.boundary_manager.get_boundary(boundary_name)
        server.implementsAuthenticationScheme = config.implements_auth
        server.sanitizesInput = config.sanitizes_input
        server.validatesInput = config.validates_input
        return server
    
    def create_external_entity(self, config: ComponentConfig, boundary_name: str) -> ExternalEntity:
        """Create an ExternalEntity component."""
        entity = ExternalEntity(config.name)
        entity.description = config.description
        entity.inBoundary = self.boundary_manager.get_boundary(boundary_name)
        entity.implementsAuthenticationScheme = config.implements_auth
        return entity
    
    def create_datastore(self, config: ComponentConfig, boundary_name: str) -> Datastore:
        """Create a Datastore component."""
        datastore = Datastore(config.name)
        datastore.description = config.description
        datastore.OS = config.os
        datastore.isHardened = config.is_hardened
        datastore.inBoundary = self.boundary_manager.get_boundary(boundary_name)
        datastore.isSQL = config.is_sql
        datastore.isEncrypted = config.is_encrypted
        return datastore


class DataFactory:
    """Factory for creating data objects."""
    
    @staticmethod
    def create_data(config: DataConfig) -> Data:
        """Create a Data object."""
        return Data(
            name=config.name,
            description=config.description,
            classification=config.classification,
            isPII=config.is_pii,
            isCredentials=config.is_credentials,
            isStored=config.is_stored
        )


class DataflowFactory:
    """Factory for creating data flows."""
    
    @staticmethod
    def create_dataflow(source: Any, destination: Any, config: DataflowConfig, data: Data) -> Dataflow:
        """Create a Dataflow object."""
        dataflow = Dataflow(source, destination, config.name)
        dataflow.protocol = config.protocol.value
        dataflow.dstPort = config.port.value
        dataflow.data = data
        if config.note:
            dataflow.note = config.note
        return dataflow


class SystemArchitecture:
    """Manages the system architecture components."""
    
    def __init__(self) -> None:
        """Initialize system architecture."""
        self.boundary_manager = BoundaryManager()
        self.component_factory = ComponentFactory(self.boundary_manager)
        self.data_factory = DataFactory()
        
        # Create components
        self.components = self._create_components()
        self.data_objects = self._create_data_objects()
    
    def _create_components(self) -> Dict[str, Any]:
        """Create all system components."""
        components = {}
        
        # Browser Client (Actor)
        components['user'] = self.component_factory.create_actor(
            ComponentConfig(
                name="Browser Client",
                description="End user accessing the web application through a browser"
            ),
            'internet'
        )
        
        # Web Application (Server)
        components['web_app'] = self.component_factory.create_server(
            ComponentConfig(
                name="Web Application",
                description="Main web application server handling user requests",
                implements_auth=True,
                sanitizes_input=True,
                validates_input=True
            ),
            'dmz'
        )
        
        # Authorization Provider (External Entity)
        components['auth_provider'] = self.component_factory.create_external_entity(
            ComponentConfig(
                name="Authorization Provider",
                description="External service for user authentication and authorization",
                implements_auth=True
            ),
            'dmz'
        )
        
        # LDAP Server
        components['ldap_server'] = self.component_factory.create_server(
            ComponentConfig(
                name="LDAP",
                description="LDAP directory service for user verification",
                implements_auth=True
            ),
            'internal'
        )
        
        # SQL Database
        components['sql_database'] = self.component_factory.create_datastore(
            ComponentConfig(
                name="SQL Database",
                description="Database storing user feedback and application data",
                is_sql=True,
                is_encrypted=True
            ),
            'internal'
        )
        
        return components
    
    def _create_data_objects(self) -> Dict[str, Data]:
        """Create all data objects."""
        data_configs = [
            DataConfig(
                name="User Credentials",
                description="Username and password for authentication",
                classification=Classification.SECRET,
                is_pii=True,
                is_credentials=True
            ),
            DataConfig(
                name="Feedback Comments",
                description="User-submitted feedback content",
                classification=Classification.PUBLIC,
                is_stored=True
            ),
            DataConfig(
                name="Authentication Verification",
                description="Authentication status and user privileges",
                classification=Classification.RESTRICTED
            ),
            DataConfig(
                name="Database Response",
                description="Success/failure response from database operations",
                classification=Classification.SENSITIVE
            )
        ]
        
        return {
            config.name.lower().replace(' ', '_'): self.data_factory.create_data(config)
            for config in data_configs
        }


class DataflowOrchestrator:
    """Orchestrates the creation of data flows between components."""
    
    def __init__(self, architecture: SystemArchitecture) -> None:
        """Initialize dataflow orchestrator."""
        self.architecture = architecture
        self.dataflow_factory = DataflowFactory()
        self.dataflows = []
        
        # Create all dataflows
        self._create_authentication_flows()
        self._create_feedback_flows()
    
    def _create_authentication_flows(self) -> None:
        """Create authentication-related data flows."""
        components = self.architecture.components
        data = self.architecture.data_objects
        
        auth_flows = [
            # User → Web App
            (components['user'], components['web_app'], 
             DataflowConfig("User Sends User Credentials", SecurityProtocol.HTTPS, NetworkPort.HTTPS, 
                          "User authentication request"), 
             data['user_credentials']),
            
            # Web App → Auth Provider
            (components['web_app'], components['auth_provider'],
             DataflowConfig("Auth Verification", SecurityProtocol.HTTPS, NetworkPort.HTTPS),
             data['user_credentials']),
            
            # Auth Provider → LDAP
            (components['auth_provider'], components['ldap_server'],
             DataflowConfig("Verifies the Privilege", SecurityProtocol.LDAPS, NetworkPort.LDAPS),
             data['user_credentials']),
            
            # LDAP → Auth Provider
            (components['ldap_server'], components['auth_provider'],
             DataflowConfig("Verified", SecurityProtocol.LDAPS, NetworkPort.LDAPS),
             data['authentication_verification']),
            
            # Auth Provider → Web App
            (components['auth_provider'], components['web_app'],
             DataflowConfig("Verified", SecurityProtocol.HTTPS, NetworkPort.HTTPS),
             data['authentication_verification']),
            
            # Web App → User
            (components['web_app'], components['user'],
             DataflowConfig("User Is Authenticated", SecurityProtocol.HTTPS, NetworkPort.HTTPS),
             data['authentication_verification'])
        ]
        
        for source, dest, config, data_obj in auth_flows:
            self.dataflows.append(
                self.dataflow_factory.create_dataflow(source, dest, config, data_obj)
            )
    
    def _create_feedback_flows(self) -> None:
        """Create feedback-related data flows."""
        components = self.architecture.components
        data = self.architecture.data_objects
        
        feedback_flows = [
            # User → Web App (Feedback)
            (components['user'], components['web_app'],
             DataflowConfig("Insert Feedback Comments", SecurityProtocol.HTTPS, NetworkPort.HTTPS),
             data['feedback_comments']),
            
            # Web App → Database
            (components['web_app'], components['sql_database'],
             DataflowConfig("Insert Query With Feedback Comments", SecurityProtocol.TLS, NetworkPort.MYSQL),
             data['feedback_comments']),
            
            # Database → Web App
            (components['sql_database'], components['web_app'],
             DataflowConfig("Success=1", SecurityProtocol.TLS, NetworkPort.MYSQL),
             data['database_response']),
            
            # Web App → User (Confirmation)
            (components['web_app'], components['user'],
             DataflowConfig("Feedback Comments Saved", SecurityProtocol.HTTPS, NetworkPort.HTTPS),
             data['database_response'])
        ]
        
        for source, dest, config, data_obj in feedback_flows:
            self.dataflows.append(
                self.dataflow_factory.create_dataflow(source, dest, config, data_obj)
            )


class ThreatModelBuilder:
    """Main builder for the threat model following SRP."""
    
    def __init__(self, model_name: str = "Web-based User Feedback System") -> None:
        """Initialize threat model builder."""
        self.tm = TM(model_name)
        self.tm.description = (
            "A web application that allows users to register, login, "
            "and submit feedback comments. The system integrates with "
            "LDAP for authentication and stores feedback in a SQL database."
        )
        self.tm.isOrdered = True
        
        # Build architecture
        self.architecture = SystemArchitecture()
        self.dataflow_orchestrator = DataflowOrchestrator(self.architecture)
    
    def get_threat_model(self) -> TM:
        """Get the built threat model."""
        return self.tm


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


class CommandLineInterface:
    """Handles command line interface operations."""
    
    def __init__(self) -> None:
        """Initialize CLI handler."""
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser."""
        parser = argparse.ArgumentParser(
            description='Activity 2 - Web-based User Feedback System Threat Model'
        )
        
        # Add all pytm-compatible arguments
        parser.add_argument('--sqldump', 
                          help='dumps all threat model elements and findings into the named sqlite file')
        parser.add_argument('--debug', action='store_true', 
                          help='print debug messages')
        parser.add_argument('--dfd', action='store_true', 
                          help='output DFD')
        parser.add_argument('--report', 
                          help='output report using the named template file')
        parser.add_argument('--exclude', 
                          help='specify threat IDs to be ignored')
        parser.add_argument('--seq', action='store_true', 
                          help='output sequential diagram')
        parser.add_argument('--list', action='store_true', 
                          help='list all available threats')
        parser.add_argument('--colormap', action='store_true', 
                          help='color the risk in the diagram')
        parser.add_argument('--describe', 
                          help='describe the properties available for a given element')
        parser.add_argument('--list-elements', action='store_true', 
                          help='list all elements which can be part of a threat model')
        parser.add_argument('--json', 
                          help='output a JSON file')
        parser.add_argument('--levels', nargs='*', type=int, 
                          help='Select levels to be drawn in the threat model')
        parser.add_argument('--stale_days', type=int, 
                          help='checks staleness of the threat model')
        
        return parser
    
    def parse_args(self) -> argparse.Namespace:
        """Parse command line arguments."""
        return self.parser.parse_args()
    
    @staticmethod
    def handle_special_commands(args: argparse.Namespace) -> bool:
        """Handle special commands that don't require building the model."""
        if args.list:
            CommandLineInterface._list_threats()
            return True
        
        if args.describe:
            _describe_classes(args.describe)
            return True
        
        if args.list_elements:
            _list_elements()
            return True
        
        return False
    
    @staticmethod
    def _list_threats() -> None:
        """List all available threats."""
        from pytm.pytm import TM
        temp_tm = TM("temp")
        temp_tm._init_threats()
        for threat in temp_tm._threats:
            threat_id = getattr(threat, 'id', 'Unknown')
            description = getattr(threat, 'description', 'No description')
            print(f"{threat_id} - {description}")


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
    
    def _export_json(self, filename: str) -> None:
        """Export threat model to JSON."""
        import json
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.threat_model.resolve(), f, indent=2)
            print(f"JSON output written to {filename}")
        except Exception as e:
            print(f"Error writing JSON file: {e}")
    
    def _print_default_info(self) -> None:
        """Print default information."""
        print("Building Web-based User Feedback System Threat Model...")
        print("Threat model processing complete!")
        print(f"Model: {self.threat_model.name}")
        print(f"Description: {self.threat_model.description}")
        print("\nUse --help to see available options")


def main() -> Optional[TM]:
    """Main function to build and process the threat model."""
    try:
        # Initialize CLI
        cli = CommandLineInterface()
        args = cli.parse_args()
        
        # Handle special commands
        if cli.handle_special_commands(args):
            return None
        
        # Build threat model
        builder = ThreatModelBuilder()
        threat_model = builder.get_threat_model()
        
        # Process threat model
        processor = ThreatModelProcessor(threat_model)
        processor.configure_model(args)
        processor.process_output(args)
        
        return threat_model
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    threat_model = main() 