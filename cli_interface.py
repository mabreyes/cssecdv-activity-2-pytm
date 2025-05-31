"""Command Line Interface Module.

This module handles the command line interface for the threat model system.
It includes functionality for:
- Argument parsing and validation
- Special command handling (list, describe, help)
- Command line argument configuration

Author: Marc Reyes <hi@marcr.xyz>

"""

import argparse

from pytm.pytm import _describe_classes, _list_elements


class CommandLineInterface:
    """Handles command line interface operations."""

    def __init__(self) -> None:
        """Initialize CLI handler."""
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser."""
        parser = argparse.ArgumentParser(
            description="Activity 2 - Web-based User Feedback System Threat Model"
        )

        # Add all pytm-compatible arguments
        parser.add_argument(
            "--sqldump",
            help="dumps all threat model elements and findings into the named "
            "sqlite file",
        )
        parser.add_argument("--debug", action="store_true", help="print debug messages")
        parser.add_argument("--dfd", action="store_true", help="output DFD")
        parser.add_argument(
            "--report", help="output report using the named template file"
        )
        parser.add_argument("--exclude", help="specify threat IDs to be ignored")
        parser.add_argument(
            "--seq", action="store_true", help="output sequential diagram"
        )
        parser.add_argument(
            "--list", action="store_true", help="list all available threats"
        )
        parser.add_argument(
            "--colormap", action="store_true", help="color the risk in the diagram"
        )
        parser.add_argument(
            "--describe", help="describe the properties available for a given element"
        )
        parser.add_argument(
            "--list-elements",
            action="store_true",
            help="list all elements which can be part of a threat model",
        )
        parser.add_argument("--json", help="output a JSON file")
        parser.add_argument(
            "--levels",
            nargs="*",
            type=int,
            help="Select levels to be drawn in the threat model",
        )
        parser.add_argument(
            "--stale_days", type=int, help="checks staleness of the threat model"
        )

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
            threat_id = getattr(threat, "id", "Unknown")
            description = getattr(threat, "description", "No description")
            print(f"{threat_id} - {description}")
