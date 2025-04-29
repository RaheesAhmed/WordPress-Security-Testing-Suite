#!/usr/bin/env python3
"""
Website Security Scanner

A tool that uses OWASP ZAP to scan websites for vulnerabilities and then
uses AI models (Google Gemini, Anthropic Claude, or OpenAI) to analyze
the results and suggest improvements.
"""

import sys
import time
import json
import argparse
import subprocess
import docker
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
import requests
from zapv2 import ZAPv2
import anthropic

# Import configuration
from config import (
    ANTHROPIC_API_KEY,
    ZAP_API_KEY,
    ZAP_PORT,
    ZAP_HOST,
    USE_DOCKER,
    DOCKER_IMAGE,
    DOCKER_CONTAINER_NAME,
    DEFAULT_SCAN_LEVEL
)

# Initialize console for rich output
console = Console()

def setup_docker_zap():
    """
    Set up ZAP in a Docker container.
    """
    try:
        # Check if ZAP is already running by trying to connect to it
        try:
            # Try to connect to ZAP API
            response = requests.get(f'http://{ZAP_HOST}:{ZAP_PORT}/JSON/core/view/version/',
                                   params={'apikey': ZAP_API_KEY}, timeout=2)
            if response.status_code == 200:
                console.print(f"[green]ZAP is already running on {ZAP_HOST}:{ZAP_PORT}[/green]")
                return True
        except requests.exceptions.RequestException:
            console.print("[yellow]ZAP is not running. Starting ZAP Docker container...[/yellow]")

        # Start ZAP using subprocess instead of Docker Python API
        # This is more reliable in some environments
        cmd = [
            "docker", "run", "--rm", "-d", "--name", DOCKER_CONTAINER_NAME,
            "-p", f"{ZAP_PORT}:{ZAP_PORT}",
            DOCKER_IMAGE, "zap.sh",
            "-daemon", "-host", "0.0.0.0", "-port", str(ZAP_PORT),
            "-config", f"api.key={ZAP_API_KEY}"
        ]

        console.print(f"[yellow]Starting ZAP with command: {' '.join(cmd)}[/yellow]")

        # Run the docker command
        process = subprocess.run(cmd, capture_output=True, text=True)

        if process.returncode != 0:
            console.print(f"[bold red]Error starting ZAP container: {process.stderr}[/bold red]")
            return False

        # Wait for ZAP to start
        console.print("[yellow]Waiting for ZAP to start...[/yellow]")

        # Try to connect to ZAP with retries
        max_retries = 10
        for i in range(max_retries):
            try:
                response = requests.get(f'http://{ZAP_HOST}:{ZAP_PORT}/JSON/core/view/version/',
                                      params={'apikey': ZAP_API_KEY}, timeout=2)
                if response.status_code == 200:
                    console.print(f"[green]ZAP started successfully after {i+1} attempts[/green]")
                    return True
            except requests.exceptions.RequestException:
                console.print(f"[yellow]Waiting for ZAP to be ready... Attempt {i+1}/{max_retries}[/yellow]")
                time.sleep(5)

        console.print("[bold red]Failed to connect to ZAP after multiple attempts[/bold red]")
        return False

    except Exception as e:
        console.print(f"[bold red]Error setting up Docker container: {e}[/bold red]")
        return False

def setup_zap_connection():
    """
    Set up connection to ZAP API.
    """
    # If using Docker, ensure the container is running
    if USE_DOCKER:
        if not setup_docker_zap():
            console.print("[bold red]Failed to set up ZAP Docker container[/bold red]")
            sys.exit(1)

    try:
        # Create ZAP API client with the API key
        console.print(f"[yellow]Connecting to ZAP API at {ZAP_HOST}:{ZAP_PORT} with API key[/yellow]")
        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={
            'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
            'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
        })

        # Test the connection
        version = zap.core.version
        console.print(f"[green]Successfully connected to ZAP API (version {version})[/green]")

        return zap
    except Exception as e:
        console.print(f"[bold red]Error connecting to ZAP: {e}[/bold red]")
        console.print("[yellow]Make sure ZAP is running and accessible with the correct API key.[/yellow]")
        sys.exit(1)

def check_zap_status(zap):
    """
    Check if ZAP is running and accessible.
    """
    try:
        version = zap.core.version
        console.print(f"[green]Connected to ZAP version {version}[/green]")
        return True
    except Exception as e:
        console.print(f"[bold red]Error checking ZAP status: {e}[/bold red]")
        return False

def scan_website(zap, target_url, scan_level="quick"):
    """
    Scan a website using ZAP.

    Args:
        zap: ZAP API client
        target_url: URL to scan
        scan_level: Level of scan (quick, standard, full)

    Returns:
        Dictionary of scan results
    """
    console.print(f"[bold blue]Starting scan of {target_url}[/bold blue]")

    try:
        # Access the target
        console.print("[yellow]Accessing target...[/yellow]")
        response = zap.urlopen(target_url)
        console.print(f"[green]Successfully accessed target. Response size: {len(response) if response else 'unknown'}[/green]")

        # Set a shorter timeout for quicker results
        console.print("[yellow]Setting scan configurations...[/yellow]")
        zap.spider.set_option_max_depth(2)  # Limit spider depth
        zap.spider.set_option_max_children(5)  # Limit number of child nodes

        # Spider the target with a maximum time
        console.print("[yellow]Spidering target (limited scope)...[/yellow]")
        scan_id = zap.spider.scan(target_url)

        # Progress bar for spidering with timeout
        max_spider_time = 60  # 1 minute max
        start_time = time.time()
        with Progress() as progress:
            spider_task = progress.add_task("[green]Spidering...", total=100)
            while int(zap.spider.status(scan_id)) < 100:
                current_status = int(zap.spider.status(scan_id))
                progress.update(spider_task, completed=current_status)
                time.sleep(1)

                # Check if we've exceeded the maximum time
                if time.time() - start_time > max_spider_time:
                    console.print("[yellow]Spider taking too long, proceeding with partial results...[/yellow]")
                    break

        console.print("[green]Spider completed or timed out[/green]")

        # Get the URLs discovered
        urls = zap.spider.results(scan_id)
        console.print(f"[green]Spider found {len(urls)} URLs[/green]")

        # Perform active scan based on scan level (with limited scope)
        console.print("[yellow]Running active scan (limited scope)...[/yellow]")

        # Set scan policy based on level
        if scan_level == "quick":
            # Use a more limited scan policy for quick scans
            try:
                # For newer ZAP versions
                zap.ascan.set_policy_attack_strength("DEFAULT", "LOW")
                zap.ascan.set_policy_alert_threshold("DEFAULT", "MEDIUM")
                # Disable some scan rules for quicker scan
                for rule_id in range(1, 100):  # Arbitrary range of rule IDs
                    try:
                        zap.ascan.set_scanner_alert_threshold(rule_id, "OFF")
                    except:
                        pass  # Ignore errors for rules that don't exist
            except Exception as e:
                console.print(f"[yellow]Warning: Could not set scan policy: {e}[/yellow]")

        # Start the scan with a time limit
        scan_id = zap.ascan.scan(target_url)

        # Progress bar for scanning with timeout
        max_scan_time = 120  # 2 minutes max
        start_time = time.time()
        with Progress() as progress:
            scan_task = progress.add_task("[green]Scanning...", total=100)
            while int(zap.ascan.status(scan_id)) < 100:
                current_status = int(zap.ascan.status(scan_id))
                progress.update(scan_task, completed=current_status)
                time.sleep(2)

                # Check if we've exceeded the maximum time
                if time.time() - start_time > max_scan_time:
                    console.print("[yellow]Scan taking too long, proceeding with partial results...[/yellow]")
                    break

        console.print("[green]Active scan completed or timed out[/green]")

        # Get the alerts
        console.print("[yellow]Retrieving alerts...[/yellow]")
        alerts = zap.core.alerts()
        console.print(f"[green]Found {len(alerts)} alerts[/green]")

        return {
            "target": target_url,
            "alerts": alerts,
            "summary": {
                "high": len([a for a in alerts if a.get('risk') == 'High']),
                "medium": len([a for a in alerts if a.get('risk') == 'Medium']),
                "low": len([a for a in alerts if a.get('risk') == 'Low']),
                "info": len([a for a in alerts if a.get('risk') == 'Informational'])
            }
        }
    except Exception as e:
        console.print(f"[bold red]Error during scan: {e}[/bold red]")
        # Return empty results in case of error
        return {
            "target": target_url,
            "alerts": [],
            "summary": {"high": 0, "medium": 0, "low": 0, "info": 0},
            "error": str(e)
        }

def format_scan_results(scan_results):
    """
    Format scan results for better readability.
    """
    target = scan_results["target"]
    alerts = scan_results["alerts"]
    summary = scan_results["summary"]

    # Create a summary table
    table = Table(title=f"Scan Results for {target}")
    table.add_column("Risk Level", style="cyan")
    table.add_column("Count", style="magenta")

    table.add_row("High", str(summary["high"]))
    table.add_row("Medium", str(summary["medium"]))
    table.add_row("Low", str(summary["low"]))
    table.add_row("Informational", str(summary["info"]))
    table.add_row("Total", str(sum(summary.values())))

    console.print(table)

    # Format detailed results
    formatted_results = {
        "target": target,
        "summary": summary,
        "vulnerabilities": []
    }

    for alert in alerts:
        formatted_results["vulnerabilities"].append({
            "name": alert.get("name", "Unknown"),
            "risk": alert.get("risk", "Unknown"),
            "confidence": alert.get("confidence", "Unknown"),
            "description": alert.get("description", ""),
            "solution": alert.get("solution", ""),
            "reference": alert.get("reference", ""),
            "url": alert.get("url", ""),
            "param": alert.get("param", ""),
            "evidence": alert.get("evidence", "")
        })

    return formatted_results

def analyze_with_claude(scan_results):
    """
    Analyze scan results using Anthropic Claude.
    """
    if not ANTHROPIC_API_KEY:
        console.print("[bold red]Error: Anthropic API key not found[/bold red]")
        return None

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    prompt = f"""
    You are a cybersecurity expert analyzing website vulnerability scan results.

    Here are the scan results from OWASP ZAP:
    {json.dumps(scan_results, indent=2)}

    Please provide:
    1. A summary of the most critical vulnerabilities found
    2. Detailed explanations of each vulnerability and its potential impact
    3. Specific recommendations for fixing each vulnerability
    4. General security improvements for the website

    Format your response in markdown.
    """

    try:
        console.print("[yellow]Sending request to Claude API...[/yellow]")
        response = client.messages.create(
            model="claude-3-7-sonnet-20250219",
            max_tokens=4000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        console.print("[green]Successfully received response from Claude[/green]")
        return response.content[0].text
    except Exception as e:
        console.print(f"[bold red]Error with Claude API: {e}[/bold red]")
        return None

def analyze_results(scan_results):
    """
    Analyze scan results using Claude.
    """
    console.print("[bold blue]Analyzing results with Claude...[/bold blue]")
    return analyze_with_claude(scan_results)

def save_results(scan_results, analysis, output_file):
    """
    Save scan results and analysis to a file.
    """
    if not output_file:
        return

    with open(output_file, 'w') as f:
        f.write("# Website Security Scan Results\n\n")
        f.write(f"Target: {scan_results['target']}\n\n")
        f.write("## Vulnerability Summary\n\n")
        f.write(f"- High: {scan_results['summary']['high']}\n")
        f.write(f"- Medium: {scan_results['summary']['medium']}\n")
        f.write(f"- Low: {scan_results['summary']['low']}\n")
        f.write(f"- Informational: {scan_results['summary']['info']}\n\n")
        f.write("## AI Analysis\n\n")
        f.write(analysis)

    console.print(f"[green]Results saved to {output_file}[/green]")

def cleanup_docker_container():
    """
    Stop and remove the ZAP Docker container.
    """
    if not USE_DOCKER:
        return

    try:
        # Check if container exists
        check_cmd = ["docker", "ps", "-a", "--filter", f"name={DOCKER_CONTAINER_NAME}", "--format", "{{.Names}}"]
        process = subprocess.run(check_cmd, capture_output=True, text=True)

        if DOCKER_CONTAINER_NAME in process.stdout:
            # Container exists, stop and remove it
            console.print(f"[yellow]Stopping and removing ZAP container {DOCKER_CONTAINER_NAME}...[/yellow]")
            stop_cmd = ["docker", "stop", DOCKER_CONTAINER_NAME]
            subprocess.run(stop_cmd, capture_output=True, text=True)

            rm_cmd = ["docker", "rm", DOCKER_CONTAINER_NAME]
            subprocess.run(rm_cmd, capture_output=True, text=True)

            console.print(f"[green]ZAP container {DOCKER_CONTAINER_NAME} removed[/green]")
        else:
            console.print(f"[yellow]ZAP container {DOCKER_CONTAINER_NAME} not found[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Error cleaning up Docker container: {e}[/bold red]")

def main():
    """
    Main function to run the security scanner.
    """
    parser = argparse.ArgumentParser(description="Website Security Scanner using ZAP and Claude AI")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--level", choices=["quick", "standard", "full"], default=DEFAULT_SCAN_LEVEL,
                        help="Scan level (quick, standard, full)")
    parser.add_argument("--output", help="Output file to save results")
    parser.add_argument("--no-docker", action="store_true", help="Don't use Docker for ZAP (use local ZAP instance)")
    parser.add_argument("--cleanup", action="store_true", help="Stop and remove Docker container after scan")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode with more verbose output")
    args = parser.parse_args()

    # Override Docker setting if --no-docker is specified
    global USE_DOCKER
    if args.no_docker:
        USE_DOCKER = False

    # Print banner
    console.print(Panel.fit(
        "[bold blue]Website Security Scanner[/bold blue]\n"
        "[cyan]Powered by OWASP ZAP and Claude AI[/cyan]",
        border_style="green"
    ))

    try:
        # Connect to ZAP
        zap = setup_zap_connection()

        # Check ZAP status
        if not check_zap_status(zap):
            console.print("[bold red]Error: ZAP is not running or not accessible[/bold red]")
            console.print("[yellow]Please start ZAP and try again.[/yellow]")
            sys.exit(1)

        # Scan the website
        console.print(f"[bold blue]Starting scan of {args.url} with {args.level} scan level[/bold blue]")
        scan_results = scan_website(zap, args.url, args.level)

        # Check if scan had errors
        if "error" in scan_results:
            console.print(f"[bold red]Scan completed with errors: {scan_results.get('error')}[/bold red]")
            console.print("[yellow]Continuing with partial results...[/yellow]")

        # Format the results
        console.print("[yellow]Formatting scan results...[/yellow]")
        formatted_results = format_scan_results(scan_results)

        # Analyze the results
        console.print("[yellow]Analyzing results with Claude AI...[/yellow]")
        analysis = analyze_results(formatted_results)

        if analysis:
            console.print("\n[bold green]Analysis Results:[/bold green]")
            console.print(Panel(analysis, border_style="blue"))

            # Save results if output file is specified
            if args.output:
                save_results(formatted_results, analysis, args.output)
                console.print(f"[green]Results saved to {args.output}[/green]")
        else:
            console.print("[bold red]Failed to analyze results[/bold red]")

    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        if args.debug:
            import traceback
            console.print(f"[red]{traceback.format_exc()}[/red]")
        sys.exit(1)

    finally:
        # Clean up Docker container if requested
        if args.cleanup and USE_DOCKER:
            cleanup_docker_container()

if __name__ == "__main__":
    main()
