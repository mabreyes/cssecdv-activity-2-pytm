#!/usr/bin/env python3
"""Report Generation Utility for Web Feedback System Threat Model.

This module provides utilities to generate various outputs from the threat model:
- Data Flow Diagrams (DFD)
- Sequence Diagrams
- Threat Reports
- JSON exports

Author: Marc Reyes <hi@marcr.xyz>

Usage:
    python generate_reports.py dfd
    python generate_reports.py seq
    python generate_reports.py report
"""

import sys
from pathlib import Path


def generate_dfd() -> None:
    """Generate Data Flow Diagram using the threat model."""
    print("Generating Data Flow Diagram...")

    # Import and run the threat model with DFD output
    from web_feedback_system_dfd import ThreatModelBuilder

    try:
        # Build the threat model
        model_builder = ThreatModelBuilder()
        threat_model = model_builder.get_threat_model()

        # Generate DFD output
        sys.argv = ["web_feedback_system_dfd.py", "--dfd"]
        threat_model.process()

        print("DFD generation complete!")
        print(
            "To generate PNG: python3 web_feedback_system_dfd.py --dfd | "
            "dot -Tpng -o web_feedback_system_dfd.png"
        )

    except Exception as e:
        print(f"Error generating DFD: {e}")


def generate_sequence_diagram() -> None:
    """Generate sequence diagram using the threat model."""
    print("Generating Sequence Diagram...")

    from web_feedback_system_dfd import ThreatModelBuilder

    try:
        # Build the threat model
        model_builder = ThreatModelBuilder()
        threat_model = model_builder.get_threat_model()

        # Generate sequence diagram output
        sys.argv = ["web_feedback_system_dfd.py", "--seq"]
        threat_model.process()

        print("Sequence diagram generation complete!")
        print(
            "To generate PNG: python3 web_feedback_system_dfd.py --seq | "
            "java -jar plantuml.jar -tpng -pipe > sequence.png"
        )

    except Exception as e:
        print(f"Error generating sequence diagram: {e}")


def generate_threat_report() -> None:
    """Generate comprehensive threat report."""
    print("Generating Threat Report...")

    # Create output directory
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # Create a comprehensive markdown report
    report_template = """# Web-based User Feedback System - Threat Model Report

## System Overview

**System Name:** Web-based User Feedback System

**Description:** A web application that allows users to register, login, and
submit feedback comments. The system integrates with LDAP for authentication
and stores feedback in a SQL database.

## System Architecture

The system consists of the following components:

### Components
- **Browser Client**: End user interface
- **Web Application**: Main application server (DMZ)
- **Authorization Provider**: External authentication service
- **LDAP Server**: Directory service for user verification
- **SQL Database**: Data storage for feedback and user information

### Trust Boundaries
- **Internet**: External user access
- **DMZ**: Web-facing services
- **Internal Network**: Backend services and data storage

## Data Flows

### Authentication Flow
1. User sends credentials to Web Application
2. Web Application forwards to Authorization Provider
3. Authorization Provider verifies with LDAP
4. LDAP responds with verification status
5. Authorization Provider confirms to Web Application
6. Web Application authenticates user

### Feedback Submission Flow
1. Authenticated user submits feedback
2. Web Application processes and validates input
3. Web Application stores feedback in SQL Database
4. Database confirms successful storage
5. Web Application notifies user of successful submission

## Identified Threats

### High Priority Threats
- **SQL Injection**: Malicious input could compromise database integrity
- **Authentication Bypass**: Potential privilege escalation vulnerabilities
- **Credential Theft**: Man-in-the-middle attacks on authentication flows

### Medium Priority Threats
- **Session Hijacking**: Unauthorized access through session manipulation
- **LDAP Injection**: Potential directory service compromise
- **Data Tampering**: Unauthorized modification of feedback data

### Low Priority Threats
- **Denial of Service**: Resource exhaustion through feedback flooding
- **Information Disclosure**: Potential exposure of sensitive data in transit

## Security Recommendations

### Immediate Actions
1. Implement input validation and parameterized queries to prevent SQL injection
2. Use strong session management and HTTPS throughout
3. Implement rate limiting for feedback submissions
4. Regular security testing and code reviews

### Long-term Improvements
1. Implement Web Application Firewall (WAF)
2. Add comprehensive logging and monitoring
3. Regular penetration testing
4. Security awareness training for development team

## Compliance Considerations
- Ensure GDPR compliance for user data handling
- Implement appropriate data retention policies
- Regular security audits and assessments

## Technical Implementation Details

### Data Classifications
- **User Credentials**: SECRET (PII, Credentials)
- **Feedback Comments**: PUBLIC (User content)
- **Authentication Verification**: RESTRICTED (System data)
- **Database Response**: SENSITIVE (System response)

### Security Controls
- Input sanitization and validation
- Encrypted communications (HTTPS/TLS)
- Hardened system configurations
- Authentication scheme implementations

---
*Report *
"""

    try:
        report_file = output_dir / "threat_report.md"
        with open(report_file, "w") as f:
            f.write(report_template)

        print(f"Threat report saved to: {report_file}")

    except Exception as e:
        print(f"Error generating threat report: {e}")


def generate_json_export() -> None:
    """Generate JSON export of the threat model."""
    print("Generating JSON export...")

    from web_feedback_system_dfd import ThreatModelBuilder

    try:
        # Build the threat model
        model_builder = ThreatModelBuilder()
        threat_model = model_builder.get_threat_model()

        # Generate JSON output
        sys.argv = [
            "web_feedback_system_dfd.py",
            "--json",
            "output/web_feedback_system.json",
        ]
        threat_model.process()

        print("JSON export complete!")

    except Exception as e:
        print(f"Error generating JSON export: {e}")


def list_threats() -> None:
    """List all available threats in pytm."""
    print("Available threats in pytm:")

    from web_feedback_system_dfd import ThreatModelBuilder

    try:
        model_builder = ThreatModelBuilder()
        threat_model = model_builder.get_threat_model()
        sys.argv = ["web_feedback_system_dfd.py", "--list"]
        threat_model.process()

    except Exception as e:
        print(f"Error listing threats: {e}")


def show_help() -> None:
    """Show help information."""
    help_text = """
Web Feedback System Threat Model - Report Generator

Usage:
    python3 generate_reports.py <command>

Commands:
    dfd         Generate Data Flow Diagram
    seq         Generate Sequence Diagram
    report      Generate comprehensive threat report
    json        Generate JSON export
    list        List available threats
    help        Show this help message

Examples:
    python3 generate_reports.py dfd
    python3 generate_reports.py report
    python3 generate_reports.py list

To generate visual diagrams:
    python3 web_feedback_system_dfd.py --dfd | dot -Tpng -o dfd.png
    python3 web_feedback_system_dfd.py --seq | java -jar plantuml.jar \\
        -tpng -pipe > seq.png
"""
    print(help_text)


def main() -> None:
    """Handle command line arguments."""
    if len(sys.argv) < 2:
        show_help()
        return

    command = sys.argv[1].lower()

    # Create output directory
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    if command == "dfd":
        generate_dfd()
    elif command == "seq":
        generate_sequence_diagram()
    elif command == "report":
        generate_threat_report()
    elif command == "json":
        generate_json_export()
    elif command == "list":
        list_threats()
    elif command == "help":
        show_help()
    else:
        print(f"Unknown command: {command}")
        show_help()


if __name__ == "__main__":
    main()
