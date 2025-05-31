#!/usr/bin/env python3
"""Activity 2 - Threat Model - Data Flow Diagram - Web-based User Feedback System.

This module defines a threat model for a web-based user feedback system
based on the DFD shown in the provided image. The system includes:
- User registration and authentication
- Feedback submission and storage
- Integration with LDAP and Authorization Provider

Author: Generated using OWASP pytm
"""

import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from pytm import (
    TM,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    ExternalEntity,
    Server,
)

from cli_interface import CommandLineInterface
from threat_model_processor import ThreatModelProcessor


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
            "internet": Boundary("Internet"),
            "dmz": Boundary("DMZ"),
            "internal": Boundary("Internal Network"),
        }

    def get_boundary(self, name: str) -> Boundary:
        """Get boundary by name."""
        if name not in self._boundaries:
            raise ValueError(f"Unknown boundary: {name}")
        return self._boundaries[name]

    @property
    def internet(self) -> Boundary:
        """Get Internet boundary."""
        return self._boundaries["internet"]

    @property
    def dmz(self) -> Boundary:
        """Get DMZ boundary."""
        return self._boundaries["dmz"]

    @property
    def internal(self) -> Boundary:
        """Get Internal Network boundary."""
        return self._boundaries["internal"]


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

    def create_external_entity(
        self, config: ComponentConfig, boundary_name: str
    ) -> ExternalEntity:
        """Create an ExternalEntity component."""
        entity = ExternalEntity(config.name)
        entity.description = config.description
        entity.inBoundary = self.boundary_manager.get_boundary(boundary_name)
        entity.implementsAuthenticationScheme = config.implements_auth
        return entity

    def create_datastore(
        self, config: ComponentConfig, boundary_name: str
    ) -> Datastore:
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
            isStored=config.is_stored,
        )


class DataflowFactory:
    """Factory for creating data flows."""

    @staticmethod
    def create_dataflow(
        source: Any, destination: Any, config: DataflowConfig, data: Data
    ) -> Dataflow:
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
        # Browser Client (Actor)
        user = self.component_factory.create_actor(
            ComponentConfig(
                name="Browser Client",
                description="End user accessing the web application through a browser",
            ),
            "internet",
        )

        # Web Application (Server)
        web_app = self.component_factory.create_server(
            ComponentConfig(
                name="Web Application",
                description="Main web application server handling user requests",
                implements_auth=True,
                sanitizes_input=True,
                validates_input=True,
            ),
            "dmz",
        )

        # Authorization Provider (External Entity)
        auth_provider = self.component_factory.create_external_entity(
            ComponentConfig(
                name="Authorization Provider",
                description="External service for user authentication and "
                "authorization",
                implements_auth=True,
            ),
            "dmz",
        )

        # LDAP Server
        ldap_server = self.component_factory.create_server(
            ComponentConfig(
                name="LDAP",
                description="LDAP directory service for user verification",
                implements_auth=True,
            ),
            "internal",
        )

        # SQL Database
        sql_database = self.component_factory.create_datastore(
            ComponentConfig(
                name="SQL Database",
                description="Database storing user feedback and application data",
                is_sql=True,
                is_encrypted=True,
            ),
            "internal",
        )

        return {
            "user": user,
            "web_app": web_app,
            "auth_provider": auth_provider,
            "ldap_server": ldap_server,
            "sql_database": sql_database,
        }

    def _create_data_objects(self) -> Dict[str, Data]:
        """Create all data objects."""
        data_configs = [
            DataConfig(
                name="User Credentials",
                description="Username and password for authentication",
                classification=Classification.SECRET,
                is_pii=True,
                is_credentials=True,
            ),
            DataConfig(
                name="Feedback Comments",
                description="User-submitted feedback content",
                classification=Classification.PUBLIC,
                is_stored=True,
            ),
            DataConfig(
                name="Authentication Verification",
                description="Authentication status and user privileges",
                classification=Classification.RESTRICTED,
            ),
            DataConfig(
                name="Database Response",
                description="Success/failure response from database operations",
                classification=Classification.SENSITIVE,
            ),
        ]

        return {
            config.name.lower().replace(" ", "_"): self.data_factory.create_data(config)
            for config in data_configs
        }


class DataflowOrchestrator:
    """Orchestrates the creation of data flows between components."""

    def __init__(self, architecture: SystemArchitecture) -> None:
        """Initialize dataflow orchestrator."""
        self.architecture = architecture
        self.dataflow_factory = DataflowFactory()
        self.dataflows: List[Dataflow] = []

        # Create all dataflows
        self._create_authentication_flows()
        self._create_feedback_flows()

    def _create_authentication_flows(self) -> None:
        """Create authentication-related data flows."""
        components = self.architecture.components
        data = self.architecture.data_objects

        auth_flows = [
            # User → Web App
            (
                components["user"],
                components["web_app"],
                DataflowConfig(
                    "User Sends User Credentials",
                    SecurityProtocol.HTTPS,
                    NetworkPort.HTTPS,
                    "User authentication request",
                ),
                data["user_credentials"],
            ),
            # Web App → Auth Provider
            (
                components["web_app"],
                components["auth_provider"],
                DataflowConfig(
                    "Auth Verification", SecurityProtocol.HTTPS, NetworkPort.HTTPS
                ),
                data["user_credentials"],
            ),
            # Auth Provider → LDAP
            (
                components["auth_provider"],
                components["ldap_server"],
                DataflowConfig(
                    "Verifies the Privilege", SecurityProtocol.LDAPS, NetworkPort.LDAPS
                ),
                data["user_credentials"],
            ),
            # LDAP → Auth Provider
            (
                components["ldap_server"],
                components["auth_provider"],
                DataflowConfig("Verified", SecurityProtocol.LDAPS, NetworkPort.LDAPS),
                data["authentication_verification"],
            ),
            # Auth Provider → Web App
            (
                components["auth_provider"],
                components["web_app"],
                DataflowConfig("Verified", SecurityProtocol.HTTPS, NetworkPort.HTTPS),
                data["authentication_verification"],
            ),
            # Web App → User
            (
                components["web_app"],
                components["user"],
                DataflowConfig(
                    "User Is Authenticated", SecurityProtocol.HTTPS, NetworkPort.HTTPS
                ),
                data["authentication_verification"],
            ),
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
            (
                components["user"],
                components["web_app"],
                DataflowConfig(
                    "Insert Feedback Comments",
                    SecurityProtocol.HTTPS,
                    NetworkPort.HTTPS,
                ),
                data["feedback_comments"],
            ),
            # Web App → Database
            (
                components["web_app"],
                components["sql_database"],
                DataflowConfig(
                    "Insert Query With Feedback Comments",
                    SecurityProtocol.TLS,
                    NetworkPort.MYSQL,
                ),
                data["feedback_comments"],
            ),
            # Database → Web App
            (
                components["sql_database"],
                components["web_app"],
                DataflowConfig("Success=1", SecurityProtocol.TLS, NetworkPort.MYSQL),
                data["database_response"],
            ),
            # Web App → User (Confirmation)
            (
                components["web_app"],
                components["user"],
                DataflowConfig(
                    "Feedback Comments Saved", SecurityProtocol.HTTPS, NetworkPort.HTTPS
                ),
                data["database_response"],
            ),
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


def main() -> Optional[TM]:
    """Build and process the threat model."""
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
