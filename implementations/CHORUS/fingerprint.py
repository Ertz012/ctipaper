import json
import re
import ipaddress
import urllib.parse
import hashlib

def extract_atomic_ioc_from_pattern(pattern: str) -> list[tuple[str, str]]:
    # Regular expression to extract matches from STIX patterns
    # Handles: [field = 'value'] or [field = "value"]
    # Field could be: ipv4-addr:value, domain-name:value, file:hashes.sha-256, etc.
    pattern = pattern.strip()
    # Find all occurrences of something like: object-type:property-path [=|!=|>|<|...] 'value'
    # We focus on equality checks (=) for simplicity and reliability
    matches = re.findall(r"([\w\-]+:(?:hashes(?:\.[\w\-]+|(?:\.'?[\w\-]+'?))|value))\s*=\s*'([^']+)'", pattern)
    extracted = []
    for field, val in matches:
        if 'hashes' in field:
            # E.g., file:hashes.SHA-256 or file:hashes.'SHA-256'
            parts = field.split('.')
            hash_type = parts[-1].replace("'", "").replace('"', '').lower()
            extracted.append((hash_type, val))
        else:
            obs_type = field.split(':')[0]
            extracted.append((obs_type, val))
    return extracted

def normalize_observable(obs_type: str, value: str) -> str:
    obs_type = obs_type.lower().strip()
    value = value.strip()
    
    if obs_type in ('ipv4-addr', 'ipv4'):
        try:
            return f"ipv4:{ipaddress.IPv4Address(value)}"
        except ValueError:
            return f"ipv4:{value.lower()}"
    elif obs_type in ('ipv6-addr', 'ipv6'):
        try:
            return f"ipv6:{ipaddress.IPv6Address(value).compressed}"
        except ValueError:
            return f"ipv6:{value.lower()}"
    elif obs_type in ('domain-name', 'domain'):
        # Decode IDN and lowercase, strip trailing dot
        val = value.rstrip('.')
        try:
            val_idn = val.encode('idna').decode('utf-8').lower()
            return f"domain:{val_idn}"
        except Exception:
            return f"domain:{val.lower()}"
    elif obs_type == 'url':
        # URL normalization
        try:
            parsed = urllib.parse.urlparse(value)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            # Remove default ports
            if scheme == 'http' and netloc.endswith(':80'):
                netloc = netloc[:-3]
            elif scheme == 'https' and netloc.endswith(':443'):
                netloc = netloc[:-4]
            path = parsed.path
            # Normalize path (remove double slashes)
            path = re.sub(r'//+', '/', path)
            query = parsed.query
            normalized_url = urllib.parse.urlunparse((scheme, netloc, path, '', query, ''))
            return f"url:{normalized_url}"
        except Exception:
            return f"url:{value.lower()}"
    elif obs_type in ('file', 'hash', 'sha-256', 'sha-1', 'md5', 'sha256', 'sha1'):
        # Lowercase hex
        return f"hash:{value.lower()}"
    elif obs_type in ('attack-pattern', 'mitre'):
        return f"mitre:{value.upper()}"
    elif obs_type in ('vulnerability', 'cve'):
        return f"cve:{value.upper()}"
    else:
        return f"{obs_type}:{value.lower()}"

class STIXFingerprint:
    @staticmethod
    def compute(stix_bundle_str: str) -> bytes:
        try:
            bundle = json.loads(stix_bundle_str)
        except json.JSONDecodeError:
            # Fallback for plain string inputs during testing
            h = hashlib.sha256(stix_bundle_str.encode('utf-8')).digest()
            return h
            
        objects = bundle.get('objects', [])
        observables = []
        
        for obj in objects:
            obj_type = obj.get('type')
            
            if obj_type == 'indicator':
                pattern = obj.get('pattern', '')
                extracted = extract_atomic_ioc_from_pattern(pattern)
                for o_type, o_val in extracted:
                    observables.append(normalize_observable(o_type, o_val))
            
            elif obj_type in ('ipv4-addr', 'ipv6-addr', 'domain-name', 'url'):
                val = obj.get('value')
                if val:
                    observables.append(normalize_observable(obj_type, val))
                    
            elif obj_type == 'file':
                hashes = obj.get('hashes', {})
                for h_type, h_val in hashes.items():
                    observables.append(normalize_observable(h_type, h_val))
                name = obj.get('name')
                if name:
                    observables.append(normalize_observable('file-name', name))
                    
            elif obj_type == 'attack-pattern':
                refs = obj.get('external_references', [])
                mitre_id = None
                for ref in refs:
                    if ref.get('source_name') == 'mitre-attack':
                        mitre_id = ref.get('external_id')
                        break
                if mitre_id:
                    observables.append(normalize_observable('attack-pattern', mitre_id))
                    
            elif obj_type == 'vulnerability':
                name = obj.get('name')
                if name and name.upper().startswith('CVE-'):
                    observables.append(normalize_observable('vulnerability', name))
        
        if not observables:
            # Fallback if no indicators/observables were found
            # Hash the serialized bundle without space formatting
            h = hashlib.sha256(json.dumps(bundle, sort_keys=True).encode('utf-8')).digest()
            return h
            
        # Deduplicate and sort
        unique_sorted = sorted(list(set(observables)))
        
        # Concatenate using 0x1F unit separator
        concat_str = "\x1F".join(unique_sorted)
        
        # Return SHA-256 digest
        return hashlib.sha256(concat_str.encode('utf-8')).digest()
