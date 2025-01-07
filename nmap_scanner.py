#!/usr/bin/env python3

import subprocess
import datetime
import os
import xml.etree.ElementTree as ET
import glob
import re
import json
import xmltodict
from typing import List, Dict, Union, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

class XMLProcessor:
    """Class to handle XML processing and conversion"""
    
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        print(f"\n[XMLProcessor] Initialized with directory: {base_dir}")
        
    def has_table_tag(self, xml_file: str) -> bool:
        """Check if XML file contains a table tag"""
        print(f"[XMLProcessor] Checking for table tags in: {os.path.basename(xml_file)}")
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            tables = root.findall('.//table')
            result = len(tables) > 0
            print(f"[XMLProcessor] Found {len(tables)} table tags in {os.path.basename(xml_file)}")
            return result
        except ET.ParseError:
            print(f"[XMLProcessor] Error parsing {xml_file}")
            return False
        except Exception as e:
            print(f"[XMLProcessor] Error processing {xml_file}: {str(e)}")
            return False

    def remove_task_tags(self, xml_file: str) -> bool:
        """Remove taskbegin and taskend tags from XML file"""
        print(f"[XMLProcessor] Removing task tags from: {os.path.basename(xml_file)}")
        try:
            with open(xml_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            original_length = len(lines)
            cleaned_lines = [
                line for line in lines 
                if not any(tag in line for tag in ['<taskbegin', '<taskend', '<taskprogress'])
            ]
            removed_lines = original_length - len(cleaned_lines)
            print(f"[XMLProcessor] Removed {removed_lines} task-related lines")
            
            final_lines = []
            prev_empty = False
            empty_lines_removed = 0
            for line in cleaned_lines:
                is_empty = not line.strip()
                if not (is_empty and prev_empty):
                    final_lines.append(line)
                else:
                    empty_lines_removed += 1
                prev_empty = is_empty
            
            print(f"[XMLProcessor] Removed {empty_lines_removed} empty lines")
            
            with open(xml_file, 'w', encoding='utf-8') as f:
                f.writelines(final_lines)
            
            print(f"[XMLProcessor] Successfully cleaned {os.path.basename(xml_file)}")
            return True
        except Exception as e:
            print(f"[XMLProcessor] Error cleaning {xml_file}: {str(e)}")
            return False

    def clean_dict(self, d: Union[Dict, List, str]) -> Union[Dict, List, str]:
        """Remove @ and # symbols from dictionary keys recursively"""
        if not isinstance(d, dict):
            return d
        
        cleaned = {}
        for k, v in d.items():
            new_key = k.replace('@', '').replace('#', '')
            
            if isinstance(v, dict):
                cleaned[new_key] = self.clean_dict(v)
            elif isinstance(v, list):
                cleaned[new_key] = [self.clean_dict(item) if isinstance(item, dict) else item for item in v]
            else:
                cleaned[new_key] = v
        return cleaned

    def convert_to_json(self, xml_file: str) -> bool:
        """Convert XML file to JSON format"""
        print(f"[XMLProcessor] Converting to JSON: {os.path.basename(xml_file)}")
        try:
            with open(xml_file, 'r', encoding='utf-8') as f:
                xml_content = f.read()
            print(f"[XMLProcessor] Read {len(xml_content)} bytes from XML file")
            
            print("[XMLProcessor] Parsing XML content...")
            xml_dict = xmltodict.parse(xml_content)
            
            print("[XMLProcessor] Cleaning dictionary keys...")
            cleaned_dict = self.clean_dict(xml_dict)
            
            json_file = xml_file.replace('.xml', '.json')
            print(f"[XMLProcessor] Writing JSON to: {os.path.basename(json_file)}")
            
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(cleaned_dict, f, indent=2, ensure_ascii=False)
            
            print(f"[XMLProcessor] Successfully converted {os.path.basename(xml_file)} to JSON")
            return True
        except Exception as e:
            print(f"[XMLProcessor] Error converting {xml_file} to JSON: {str(e)}")
            return False

    def combine_json_files(self) -> bool:
        """Combine all JSON files in the directory into one"""
        print("\n[XMLProcessor] Starting JSON combination process...")
        try:
            json_files = [f for f in glob.glob(os.path.join(self.base_dir, "*.json")) 
                         if not f.endswith('combined_scan_results.json')]
            
            print(f"[XMLProcessor] Found {len(json_files)} JSON files to combine")
            if not json_files:
                print("[XMLProcessor] No JSON files found to combine")
                return False
            
            combined_data = {
                "combined_scans": {
                    "metadata": [],
                    "total_scans": len(json_files),
                    "hosts": []
                }
            }
            
            total_hosts = 0
            for json_file in json_files:
                print(f"\n[XMLProcessor] Processing: {os.path.basename(json_file)}")
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    scan_data = data.get('nmaprun', {})
                    
                    print("[XMLProcessor] Extracting metadata...")
                    metadata = {
                        "scanner": scan_data.get('scanner'),
                        "args": scan_data.get('args'),
                        "start": scan_data.get('start'),
                        "startstr": scan_data.get('startstr'),
                        "version": scan_data.get('version'),
                        "xmloutputversion": scan_data.get('xmloutputversion'),
                        "scaninfo": scan_data.get('scaninfo'),
                        "port_range": os.path.basename(json_file).replace('scan_', '').replace('.json', '')
                    }
                    combined_data["combined_scans"]["metadata"].append(metadata)
                    
                    if 'host' in scan_data:
                        hosts = scan_data['host']
                        if not isinstance(hosts, list):
                            hosts = [hosts]
                        print(f"[XMLProcessor] Found {len(hosts)} hosts in this scan")
                        for host in hosts:
                            host['port_range'] = metadata['port_range']
                            combined_data["combined_scans"]["hosts"].append(host)
                            total_hosts += 1
            
            output_file = os.path.join(self.base_dir, "combined_scan_results.json")
            print(f"\n[XMLProcessor] Writing combined data to: {os.path.basename(output_file)}")
            print(f"[XMLProcessor] Total metadata entries: {len(combined_data['combined_scans']['metadata'])}")
            print(f"[XMLProcessor] Total hosts combined: {total_hosts}")
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(combined_data, f, indent=2, ensure_ascii=False)
            
            print(f"[XMLProcessor] Successfully created combined JSON file")
            return True
        except Exception as e:
            print(f"[XMLProcessor] Error combining JSON files: {str(e)}")
            return False

    def process_xml_files(self) -> None:
        """Process all XML files in the directory"""
        if not os.path.exists(self.base_dir):
            print(f"Directory {self.base_dir} not found!")
            return
        
        xml_files = glob.glob(os.path.join(self.base_dir, "*.xml"))
        
        if not xml_files:
            print(f"No XML files found in {self.base_dir}")
            return
        
        print(f"Found {len(xml_files)} XML files")
        deleted = kept = cleaned = converted = 0
        
        # First pass: Delete files without table tags
        for xml_file in xml_files:
            if self.has_table_tag(xml_file):
                kept += 1
                print(f"Keeping {os.path.basename(xml_file)} (contains table tag)", end='\r')
            else:
                try:
                    os.remove(xml_file)
                    deleted += 1
                    print(f"Deleted {os.path.basename(xml_file)} (no table tag)", end='\r')
                except Exception as e:
                    print(f"\nError deleting {xml_file}: {str(e)}")
        
        print("\n\nRemoving taskbegin/taskend tags from remaining files...")
        
        # Second pass: Clean remaining files
        remaining_files = glob.glob(os.path.join(self.base_dir, "*.xml"))
        for xml_file in remaining_files:
            if self.remove_task_tags(xml_file):
                cleaned += 1
                print(f"Cleaned {os.path.basename(xml_file)}", end='\r')
        
        print("\n\nConverting cleaned files to JSON...")
        
        # Third pass: Convert to JSON
        for xml_file in remaining_files:
            if self.convert_to_json(xml_file):
                converted += 1
                print(f"Converted {os.path.basename(xml_file)} to JSON", end='\r')
        
        print(f"\nProcessing completed!")
        print(f"Files kept: {kept}")
        print(f"Files deleted: {deleted}")
        print(f"Files cleaned of task tags: {cleaned}")
        print(f"Files converted to JSON: {converted}")
        
        # Fourth pass: Combine JSON files
        print("\nCombining JSON files...")
        self.combine_json_files()

class NmapScanner:
    """Class to handle nmap scanning operations"""
    
    def __init__(self, target: str, output_dir: str = "nmap_scans", threads: int = 100):
        print(f"\n[NmapScanner] Initializing scanner...")
        self.target = target
        self.output_dir = f"{output_dir}_{target.replace('.', '_')}"
        self.threads = threads
        print(f"[NmapScanner] Target: {target}")
        print(f"[NmapScanner] Output directory: {self.output_dir}")
        print(f"[NmapScanner] Number of threads: {threads}")
        
        print("[NmapScanner] Calculating port ranges...")
        self.port_ranges = self._calculate_port_ranges()
        print(f"[NmapScanner] Created {len(self.port_ranges)} port ranges")
        
        print(f"[NmapScanner] Creating output directory: {self.output_dir}")
        os.makedirs(self.output_dir, exist_ok=True)
    
    def _calculate_port_ranges(self) -> List[tuple]:
        """Calculate port ranges for parallel scanning"""
        total_ports = 65535
        ports_per_thread = total_ports // self.threads
        ranges = []
        
        for i in range(self.threads):
            start = i * ports_per_thread + 1
            end = start + ports_per_thread - 1 if i < self.threads - 1 else 65535
            ranges.append((start, end))
            print(f"[NmapScanner] Range {i+1}: ports {start}-{end} ({end-start+1} ports)")
        
        return ranges
    
    def scan_ports(self, start_port: int, end_port: int) -> Optional[str]:
        """Perform nmap scan for a specific port range"""
        print(f"\n[NmapScanner] Starting scan for ports {start_port}-{end_port}")
        try:
            output_file = os.path.join(self.output_dir, f"scan_{start_port}-{end_port}")
            
            command = [
                "nmap",
                "-A",        # Enable OS detection, version detection, script scanning, and traceroute
                "-vv",       # Very verbose output
                "--open",    # Only show open ports
                "-p", f"{start_port}-{end_port}",
                "-oX", f"{output_file}.xml",  # XML output
                self.target
            ]
            
            print(f"[NmapScanner] Executing command: {' '.join(command)}")
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            if stdout:
                print(f"[NmapScanner] Stdout: {stdout[:200]}...")
            if stderr:
                print(f"[NmapScanner] Stderr: {stderr[:200]}...")
            
            if process.returncode == 0:
                print(f"[NmapScanner] Scan completed successfully for ports {start_port}-{end_port}")
                return output_file + ".xml"
            else:
                print(f"[NmapScanner] Error scanning ports {start_port}-{end_port}: {stderr}")
                return None
                
        except Exception as e:
            print(f"[NmapScanner] Error during scan of ports {start_port}-{end_port}: {str(e)}")
            return None
    
    def run_scan(self) -> None:
        """Run the complete nmap scan using ThreadPoolExecutor for parallel execution"""
        print(f"\n[NmapScanner] Starting parallel scan of {self.target}")
        print(f"[NmapScanner] Launching {self.threads} concurrent scans")
        
        completed_scans = []
        total_ranges = len(self.port_ranges)
        completed = 0
        
        # Create a ThreadPoolExecutor with max_workers set to number of threads
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all scan jobs immediately
            future_to_range = {
                executor.submit(self.scan_ports, start, end): (start, end)
                for start, end in self.port_ranges
            }
            
            print(f"[NmapScanner] Submitted {len(future_to_range)} scan jobs to thread pool")
            
            # Process results as they complete (in any order)
            for future in as_completed(future_to_range):
                start, end = future_to_range[future]
                try:
                    result = future.result()
                    completed += 1
                    if result:
                        completed_scans.append(result)
                        print(f"[NmapScanner] Progress: {completed}/{total_ranges} ranges completed")
                    else:
                        print(f"[NmapScanner] Scan failed for range {start}-{end}")
                except Exception as e:
                    print(f"[NmapScanner] Error in scan {start}-{end}: {str(e)}")
                    completed += 1
        
        print(f"\n[NmapScanner] All scans completed!")
        print(f"[NmapScanner] Successful scans: {len(completed_scans)}/{total_ranges}")
        
        if completed_scans:
            print("\n[NmapScanner] Starting XML processing...")
            processor = XMLProcessor(self.output_dir)
            processor.process_xml_files()
        else:
            print("\n[NmapScanner] No successful scans to process")

def main():
    """Main function to run the scanner"""
    print("\n[Main] Starting nmap scanning tool")
    target = input("[Main] Enter target host/IP: ") or "pentest-ground.com"
    threads = int(input("[Main] Enter number of threads (default 100): ") or "100")
    
    print(f"\n[Main] Creating scanner for target: {target} with {threads} threads")
    scanner = NmapScanner(target=target, threads=threads)
    scanner.run_scan()

if __name__ == "__main__":
    main() 