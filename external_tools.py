import os
import json
import subprocess
import asyncio
from logger import get_logger

logger = get_logger(__name__)

class ExternalToolManager:
    def __init__(self):
        self.tools = {
            'subfinder': {
                'check_cmd': 'subfinder -version',
                'install_cmd': 'GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder',
                'binary': 'subfinder'
            },
            'amass': {
                'check_cmd': 'amass -version',
                'install_cmd': 'GO111MODULE=on go get -v github.com/OWASP/Amass/v3/...',
                'binary': 'amass'
            },
            'assetfinder': {
                'check_cmd': 'assetfinder -h',
                'install_cmd': 'GO111MODULE=on go get -v github.com/tomnomnom/assetfinder',
                'binary': 'assetfinder'
            },
            'massdns': {
                'check_cmd': 'massdns -h',
                'install_cmd': 'git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && sudo make install',
                'binary': 'massdns'
            },
            'dnsx': {
                'check_cmd': 'dnsx -version',
                'install_cmd': 'GO111MODULE=on go get -v github.com/projectdiscovery/dnsx/cmd/dnsx',
                'binary': 'dnsx'
            },
            'nuclei': {
                'check_cmd': 'nuclei -version',
                'install_cmd': 'GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei',
                'binary': 'nuclei'
            },
            'httpx': {
                'check_cmd': 'httpx -version',
                'install_cmd': 'GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx',
                'binary': 'httpx'
            },
            'gau': {
                'check_cmd': 'gau -version',
                'install_cmd': 'GO111MODULE=on go get -v github.com/lc/gau',
                'binary': 'gau'
            },
            'dalfox': {
                'check_cmd': 'dalfox version',
                'install_cmd': 'GO111MODULE=on go get -v github.com/hahwul/dalfox/v2',
                'binary': 'dalfox'
            },
            'sqlmap': {
                'check_cmd': 'sqlmap --version',
                'install_cmd': 'git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git',
                'binary': 'sqlmap'
            },
            'nikto': {
                'check_cmd': 'nikto -Version',
                'install_cmd': 'git clone --depth 1 https://github.com/sullo/nikto.git',
                'binary': 'nikto'
            },
            'wapiti': {
                'check_cmd': 'wapiti -v',
                'install_cmd': 'pip install wapiti3',
                'binary': 'wapiti'
            }
        }
        self.ensure_tools_installed()

    def ensure_tools_installed(self):
        """Ensure all required external tools are installed"""
        for tool_name, tool_info in self.tools.items():
            try:
                subprocess.run(
                    tool_info['check_cmd'].split(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                logger.info(f"{tool_name} is installed")
            except Exception:
                logger.warning(f"{tool_name} not found, attempting to install...")
                try:
                    if 'go get' in tool_info['install_cmd']:
                        os.system(tool_info['install_cmd'])
                    elif tool_info['install_cmd'].startswith('git clone'):
                        subprocess.run(
                            tool_info['install_cmd'].split(),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        )
                    elif tool_info['install_cmd'].startswith('pip'):
                        subprocess.run(
                            tool_info['install_cmd'].split(),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        )
                    logger.info(f"Successfully installed {tool_name}")
                except Exception as e:
                    logger.error(f"Failed to install {tool_name}: {e}")

    async def run_subfinder(self, domain):
        """Run subfinder for subdomain enumeration with enhanced options"""
        try:
            # Enhanced options:
            # -all: Use all sources
            # -cs: Use certificate transparency logs
            # -recursive: Use recursive subdomain discovery
            # -t 50: Use 50 concurrent threads
            # -timeout 30: Set timeout to 30 seconds
            # -max-time 10: Set maximum running time to 10 minutes
            cmd = f"subfinder -d {domain} -silent -all -cs -recursive -t 50 -timeout 30 -max-time 10"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stdout:
                subdomains = stdout.decode().strip().split('\n')
                return list(filter(None, subdomains))
            return []
        except Exception as e:
            logger.error(f"Error running subfinder: {e}")
            return []

    async def run_nuclei(self, target):
        """Run nuclei for vulnerability scanning"""
        try:
            cmd = f"nuclei -u {target} -silent -json"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stdout:
                results = []
                for line in stdout.decode().strip().split('\n'):
                    try:
                        results.append(json.loads(line))
                    except:
                        continue
                return results
            return []
        except Exception as e:
            logger.error(f"Error running nuclei: {e}")
            return []

    async def run_httpx(self, urls):
        """Run httpx for HTTP probing"""
        try:
            input_file = 'temp_urls.txt'
            with open(input_file, 'w') as f:
                f.write('\n'.join(urls))
            
            cmd = f"httpx -silent -json -l {input_file}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            os.remove(input_file)
            
            if stdout:
                results = []
                for line in stdout.decode().strip().split('\n'):
                    try:
                        results.append(json.loads(line))
                    except:
                        continue
                return results
            return []
        except Exception as e:
            logger.error(f"Error running httpx: {e}")
            return []

    async def run_gau(self, domain):
        """Run gau for URL enumeration"""
        try:
            cmd = f"gau {domain} --json"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stdout:
                results = []
                for line in stdout.decode().strip().split('\n'):
                    try:
                        results.append(json.loads(line))
                    except:
                        continue
                return results
            return []
        except Exception as e:
            logger.error(f"Error running gau: {e}")
            return []

    async def run_enhanced_dalfox(self, urls):
        """Run enhanced dalfox scan with additional payloads"""
        try:
            input_file = 'temp_urls.txt'
            with open(input_file, 'w') as f:
                f.write('\n'.join(urls))
            
            cmd = f"dalfox file {input_file} --deep --mining-dict --skip-bav -o dalfox_results.json"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            os.remove(input_file)
            
            if os.path.exists('dalfox_results.json'):
                with open('dalfox_results.json', 'r') as f:
                    results = json.load(f)
                os.remove('dalfox_results.json')
                return results
            return []
        except Exception as e:
            logger.error(f"Error running enhanced dalfox: {e}")
            return []

    async def run_enhanced_sqlmap(self, urls):
        """Run enhanced sqlmap scan"""
        try:
            results = []
            for url in urls[:10]:  # Limit to 10 URLs for performance
                cmd = f"sqlmap -u {url} --batch --random-agent --level=5 --risk=3 --threads=10 --json-output=sqlmap_result.json"
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                
                if os.path.exists('sqlmap_result.json'):
                    with open('sqlmap_result.json', 'r') as f:
                        scan_result = json.load(f)
                    results.append(scan_result)
                    os.remove('sqlmap_result.json')
            
            return results
        except Exception as e:
            logger.error(f"Error running enhanced sqlmap: {e}")
            return []

    async def run_nikto(self, target):
        """Run nikto web server scanner"""
        try:
            cmd = f"nikto -h {target} -Format json -output nikto_results.json"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if os.path.exists('nikto_results.json'):
                with open('nikto_results.json', 'r') as f:
                    results = json.load(f)
                os.remove('nikto_results.json')
                return results
            return []
        except Exception as e:
            logger.error(f"Error running nikto: {e}")
            return []

    async def run_wapiti(self, target):
        """Run wapiti web application vulnerability scanner"""
        try:
            cmd = f"wapiti -u {target} -f json -o wapiti_results"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if os.path.exists('wapiti_results'):
                with open('wapiti_results/report.json', 'r') as f:
                    results = json.load(f)
                return results
            return []
        except Exception as e:
            logger.error(f"Error running wapiti: {e}")
            return []

    async def run_amass(self, domain):
        """Run amass for advanced subdomain enumeration"""
        try:
            # -passive: Passive gathering only
            # -timeout 10: Set timeout to 10 minutes
            # -max-dns-queries 500: Limit DNS queries
            cmd = f"amass enum -passive -d {domain} -timeout 10 -max-dns-queries 500 -json amass_output.json"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()

            if os.path.exists('amass_output.json'):
                results = []
                with open('amass_output.json', 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            if 'name' in data:
                                results.append(data['name'])
                        except:
                            continue
                os.remove('amass_output.json')
                return list(set(results))
            return []
        except Exception as e:
            logger.error(f"Error running amass: {e}")
            return []

    async def run_assetfinder(self, domain):
        """Run assetfinder for quick subdomain discovery"""
        try:
            cmd = f"assetfinder --subs-only {domain}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stdout:
                subdomains = stdout.decode().strip().split('\n')
                return list(filter(None, subdomains))
            return []
        except Exception as e:
            logger.error(f"Error running assetfinder: {e}")
            return []

    async def run_massdns(self, domains, resolvers="resolvers.txt"):
        """Run massdns for fast DNS resolution"""
        try:
            # Write domains to temporary file
            with open('domains.txt', 'w') as f:
                f.write('\n'.join(domains))

            # Ensure resolvers file exists, if not create with common resolvers
            if not os.path.exists(resolvers):
                common_resolvers = [
                    "8.8.8.8", "8.8.4.4",  # Google
                    "1.1.1.1", "1.0.0.1",  # Cloudflare
                    "9.9.9.9", "149.112.112.112"  # Quad9
                ]
                with open(resolvers, 'w') as f:
                    f.write('\n'.join(common_resolvers))

            # Run massdns
            cmd = f"massdns -r {resolvers} -t A -o J -w massdns_results.json domains.txt"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()

            resolved = set()
            if os.path.exists('massdns_results.json'):
                with open('massdns_results.json', 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            if data.get('status') == "NOERROR":
                                resolved.add(data['name'].rstrip('.'))
                        except:
                            continue
                os.remove('massdns_results.json')

            # Cleanup
            os.remove('domains.txt')
            return list(resolved)
        except Exception as e:
            logger.error(f"Error running massdns: {e}")
            return []

    async def run_dnsx(self, domains):
        """Run dnsx for DNS resolution and additional DNS records"""
        try:
            # Write domains to temporary file
            with open('domains.txt', 'w') as f:
                f.write('\n'.join(domains))

            # -a: A records
            # -aaaa: AAAA records
            # -cname: CNAME records
            # -mx: MX records
            # -json: JSON output
            cmd = f"dnsx -l domains.txt -json -a -aaaa -cname -mx -silent"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            results = []
            if stdout:
                for line in stdout.decode().strip().split('\n'):
                    try:
                        results.append(json.loads(line))
                    except:
                        continue

            # Cleanup
            os.remove('domains.txt')
            return results
        except Exception as e:
            logger.error(f"Error running dnsx: {e}")
            return []

# Create a global instance
tool_manager = ExternalToolManager()