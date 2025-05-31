#!/usr/bin/env python3
"""Visual Diagram Generator for Web Feedback System Threat Model.

This script generates visual diagrams from the threat model outputs.
Requires Graphviz for DFD generation and Java + PlantUML for sequence diagrams.

Author: Marc Reyes <hi@marcr.xyz>

Usage:
    python3 generate_visuals.py
"""

import subprocess  # nosec B404
from pathlib import Path


def check_graphviz() -> bool:
    """Check if Graphviz is installed."""
    try:
        subprocess.run(
            ["dot", "-V"], capture_output=True, check=True
        )  # nosec B603,B607
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def check_java() -> bool:
    """Check if Java is installed."""
    try:
        subprocess.run(
            ["java", "-version"], capture_output=True, check=True
        )  # nosec B603,B607
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def generate_dfd_png() -> bool:
    """Generate PNG from DFD using Graphviz."""
    print("Generating DFD PNG...")

    if not check_graphviz():
        print("Error: Graphviz not found. Please install Graphviz first.")
        print("  macOS: brew install graphviz")
        print("  Ubuntu/Debian: sudo apt-get install graphviz")
        return False

    try:
        # Generate DFD dot file and pipe to Graphviz
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        # Run the threat model to generate DFD and pipe to dot
        cmd = ["python3", "web_feedback_system_dfd.py", "--dfd"]

        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True
        )  # nosec B603
        dfd_content = result.stdout

        # Extract only the digraph content (skip the building message)
        lines = dfd_content.split("\n")
        digraph_start = -1
        for i, line in enumerate(lines):
            if line.strip().startswith("digraph tm"):
                digraph_start = i
                break

        if digraph_start >= 0:
            # Find the end of the digraph
            digraph_end = -1
            for i in range(digraph_start, len(lines)):
                if lines[i].strip() == "}" and i > digraph_start:
                    digraph_end = i
                    break

            if digraph_end >= 0:
                dot_content = "\n".join(lines[digraph_start : digraph_end + 1])

                # Save dot content to file
                dot_file = output_dir / "web_feedback_system.dot"
                with open(dot_file, "w") as f:
                    f.write(dot_content)

                # Generate PNG using dot
                png_file = output_dir / "web_feedback_system_dfd.png"
                dot_cmd = ["dot", "-Tpng", str(dot_file), "-o", str(png_file)]
                subprocess.run(dot_cmd, check=True)  # nosec B603

                print(f"DFD PNG generated: {png_file}")
                return True

        print("Error: Could not extract DFD content")
        return False

    except subprocess.CalledProcessError as e:
        print(f"Error generating DFD PNG: {e}")
        return False


def _download_plantuml() -> bool:
    """Download PlantUML JAR if not present."""
    plantuml_jar = Path("plantuml.jar")
    if plantuml_jar.exists():
        return True

    print("PlantUML JAR not found. Downloading...")
    try:
        import urllib.request

        urllib.request.urlretrieve(  # nosec B310
            "http://sourceforge.net/projects/plantuml/files/plantuml.jar/" "download",
            "plantuml.jar",
        )
        print("PlantUML JAR downloaded successfully.")
        return True
    except Exception as e:
        print(f"Error downloading PlantUML: {e}")
        print(
            "Please download plantuml.jar manually from " "http://plantuml.com/download"
        )
        return False


def _extract_plantuml_content(seq_content: str) -> str:
    """Extract PlantUML content from sequence output."""
    lines = seq_content.split("\n")
    plantuml_start = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("@startuml"):
            plantuml_start = i
            break

    if plantuml_start >= 0:
        # Find the end of the PlantUML
        plantuml_end = -1
        for i in range(plantuml_start, len(lines)):
            if lines[i].strip() == "@enduml":
                plantuml_end = i
                break

        if plantuml_end >= 0:
            return "\n".join(lines[plantuml_start : plantuml_end + 1])

    return ""


def generate_sequence_png() -> bool:
    """Generate PNG from sequence diagram using PlantUML."""
    print("Generating Sequence Diagram PNG...")

    if not check_java():
        print("Error: Java not found. Please install Java first.")
        return False

    if not _download_plantuml():
        return False

    try:
        # Generate sequence diagram and pipe to PlantUML
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        # Run the threat model to generate sequence diagram
        cmd = ["python3", "web_feedback_system_dfd.py", "--seq"]

        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True
        )  # nosec B603
        seq_content = result.stdout

        # Extract PlantUML content
        puml_content = _extract_plantuml_content(seq_content)

        if not puml_content:
            print("Error: Could not extract sequence diagram content")
            return False

        # Save PlantUML content to file
        puml_file = output_dir / "web_feedback_system.puml"
        with open(puml_file, "w") as f:
            f.write(puml_content)

        # Generate PNG using PlantUML
        plantuml_cmd = ["java", "-jar", "plantuml.jar", "-tpng", str(puml_file)]
        subprocess.run(plantuml_cmd, check=True)  # nosec B603

        png_file = output_dir / "web_feedback_system.png"
        print(f"Sequence diagram PNG generated: {png_file}")
        return True

    except subprocess.CalledProcessError as e:
        print(f"Error generating sequence diagram PNG: {e}")
        return False


def main() -> None:
    """Generate visual diagrams."""
    print("Web Feedback System Threat Model - Visual Generator")
    print("=" * 55)

    success_count = 0

    # Generate DFD PNG
    if generate_dfd_png():
        success_count += 1

    print()

    # Generate Sequence Diagram PNG
    if generate_sequence_png():
        success_count += 1

    print()
    print(f"Generated {success_count}/2 visual diagrams successfully.")

    if success_count > 0:
        print("Check the 'output' directory for generated files.")


if __name__ == "__main__":
    main()
