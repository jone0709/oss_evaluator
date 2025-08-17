import json
import os
import hashlib
import logging
import asyncio
import time
import difflib
import configparser
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Union, Tuple
from urllib.parse import urlparse, quote
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime, timedelta, UTC

# Rich formatting (optional)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
    
    # For MCP mode, we need to detect if we're running as server
    # and disable Rich console output to stdout
    import sys
    if len(sys.argv) == 1:  # MCP server mode
        console = None  # Disable Rich in MCP mode
        RICH_AVAILABLE = False
    else:
        console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


# Standard library for async support
import aiohttp
import aiofiles

# Enhanced HTTP requests
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Rich formatting (optional)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# FastMCP
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("openssf_evaluator.log")
    ]
)
logger = logging.getLogger("openssf_evaluator")

# Constants
DEFAULT_CACHE_DIR = "openssf_cache"
DEFAULT_CACHE_HOURS = 24
USER_AGENT = "Enhanced-OpenSSF-Evaluator/3.0"
OSV_API_URL = "https://api.osv.dev/v1/query"
GITHUB_API_ROOT = "https://api.github.com"
REQUEST_TIMEOUT = 15
GITHUB_REQUEST_TIMEOUT = 10
CONFIG_FILE = "openssf_config.ini"

@dataclass
class EvaluationMetrics:
    """Metrics for monitoring evaluations"""
    package_name: str
    package_manager: str
    version: Optional[str]
    duration: float
    cache_hits: int
    cache_misses: int
    api_calls: int
    vulnerability_count: int
    score: float
    risk_level: str
    timestamp: datetime

@dataclass
class PackageInfo:
    """Standardized package information"""
    name: str
    version: str
    manager: str
    description: str
    registry_url: str
    repository_url: Optional[str]
    license_name: Optional[str]
    downloads: Optional[int] = None
    stars: Optional[int] = None
    forks: Optional[int] = None
    last_updated: Optional[str] = None

class Config:
    """Configuration management with file and environment variable support"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or CONFIG_FILE
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.cache_duration_hours = int(os.getenv("CACHE_DURATION_HOURS", "24"))
        self.max_retries = int(os.getenv("MAX_RETRIES", "3"))
        self.request_timeout = int(os.getenv("REQUEST_TIMEOUT", "15"))
        self.max_alternatives = int(os.getenv("MAX_ALTERNATIVES", "10"))
        self.enable_sbom = os.getenv("ENABLE_SBOM", "true").lower() == "true"
        self.enable_supply_chain_checks = os.getenv("ENABLE_SUPPLY_CHAIN", "true").lower() == "true"
        self.max_concurrent_requests = int(os.getenv("MAX_CONCURRENT_REQUESTS", "10"))
        
        # Load from config file if it exists
        if os.path.exists(self.config_file):
            self._load_config_file()
            logger.info(f"Configuration loaded from {self.config_file}")
        else:
            self._create_default_config()
    
    def _load_config_file(self):
        """Load configuration from INI file"""
        config = configparser.ConfigParser()
        config.read(self.config_file)
        
        if 'general' in config:
            self.cache_duration_hours = config.getint('general', 'cache_duration_hours', fallback=self.cache_duration_hours)
            self.max_retries = config.getint('general', 'max_retries', fallback=self.max_retries)
            self.request_timeout = config.getint('general', 'request_timeout', fallback=self.request_timeout)
            self.max_alternatives = config.getint('general', 'max_alternatives', fallback=self.max_alternatives)
            self.enable_sbom = config.getboolean('general', 'enable_sbom', fallback=self.enable_sbom)
            self.enable_supply_chain_checks = config.getboolean('general', 'enable_supply_chain_checks', fallback=self.enable_supply_chain_checks)
            self.max_concurrent_requests = config.getint('general', 'max_concurrent_requests', fallback=self.max_concurrent_requests)
        
        if 'auth' in config:
            file_token = config.get('auth', 'github_token', fallback=None)
            if file_token and not self.github_token:
                self.github_token = file_token
    
    def _create_default_config(self):
        """Create a default configuration file"""
        config = configparser.ConfigParser()
        config['general'] = {
            'cache_duration_hours': str(self.cache_duration_hours),
            'max_retries': str(self.max_retries),
            'request_timeout': str(self.request_timeout),
            'max_alternatives': str(self.max_alternatives),
            'enable_sbom': str(self.enable_sbom).lower(),
            'enable_supply_chain_checks': str(self.enable_supply_chain_checks).lower(),
            'max_concurrent_requests': str(self.max_concurrent_requests)
        }
        config['auth'] = {
            'github_token': '# Set your GitHub token here or use GITHUB_TOKEN env var'
        }
        
        try:
            with open(self.config_file, 'w') as f:
                config.write(f)
            logger.info(f"Created default configuration file: {self.config_file}")
        except Exception as e:
            logger.warning(f"Could not create config file: {e}")

class MetricsCollector:
    """Collect and track evaluation metrics"""
    
    def __init__(self):
        self.metrics: List[EvaluationMetrics] = []
        self.total_evaluations = 0
        self.total_cache_hits = 0
        self.total_cache_misses = 0
        self.total_api_calls = 0
        self.start_time = datetime.now(UTC)
    
    def record_evaluation(self, metrics: EvaluationMetrics):
        """Record an evaluation metric"""
        self.metrics.append(metrics)
        self.total_evaluations += 1
        self.total_cache_hits += metrics.cache_hits
        self.total_cache_misses += metrics.cache_misses
        self.total_api_calls += metrics.api_calls
        
        # Keep only last 1000 evaluations to prevent memory bloat
        if len(self.metrics) > 1000:
            self.metrics = self.metrics[-1000:]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        uptime = datetime.now(UTC) - self.start_time
        cache_hit_rate = (self.total_cache_hits / (self.total_cache_hits + self.total_cache_misses)) * 100 if (self.total_cache_hits + self.total_cache_misses) > 0 else 0
        
        recent_metrics = self.metrics[-100:] if len(self.metrics) >= 100 else self.metrics
        avg_duration = sum(m.duration for m in recent_metrics) / len(recent_metrics) if recent_metrics else 0
        avg_score = sum(m.score for m in recent_metrics) / len(recent_metrics) if recent_metrics else 0
        
        risk_distribution = {}
        for metric in recent_metrics:
            risk_distribution[metric.risk_level] = risk_distribution.get(metric.risk_level, 0) + 1
        
        return {
            "uptime_hours": uptime.total_seconds() / 3600,
            "total_evaluations": self.total_evaluations,
            "cache_hit_rate": cache_hit_rate,
            "total_api_calls": self.total_api_calls,
            "average_duration_seconds": avg_duration,
            "average_score": avg_score,
            "risk_level_distribution": risk_distribution,
            "evaluations_per_hour": self.total_evaluations / (uptime.total_seconds() / 3600) if uptime.total_seconds() > 0 else 0
        }

class CacheManager:
    """Enhanced cache manager with better performance and monitoring"""
    
    def __init__(self, cache_dir: str = DEFAULT_CACHE_DIR, cache_duration_hours: int = DEFAULT_CACHE_HOURS):
        self.cache_dir = Path(cache_dir)
        self.cache_duration = timedelta(hours=cache_duration_hours)
        self.cache_dir.mkdir(exist_ok=True)
        self.hits = 0
        self.misses = 0
        logger.info(f"Cache initialized at '{self.cache_dir}' with {cache_duration_hours}h duration")
    
    def _get_cache_key(self, url: str, method: str = "GET", body: Optional[Any] = None) -> str:
        """Generate cache key with SHA256 hash"""
        key_data = {"url": url, "method": method.upper()}
        if body is not None:
            try:
                key_data["body"] = json.dumps(body, sort_keys=True, separators=(",", ":"))
            except (TypeError, ValueError):
                key_data["body"] = str(body)
        
        raw = json.dumps(key_data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    
    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path"""
        return self.cache_dir / f"{key}.json"
    
    def get(self, url: str, method: str = "GET", body: Optional[Any] = None) -> Optional[Any]:
        """Get cached data if valid"""
        key = self._get_cache_key(url, method, body)
        cache_path = self._get_cache_path(key)
        
        try:
            if not cache_path.exists():
                self.misses += 1
                return None
            
            with open(cache_path, 'r', encoding='utf-8') as f:
                payload = json.load(f)
            
            timestamp_str = payload.get("timestamp")
            if not timestamp_str:
                cache_path.unlink(missing_ok=True)
                self.misses += 1
                return None
            
            timestamp = datetime.fromisoformat(timestamp_str)
            if datetime.now(UTC) - timestamp < self.cache_duration:
                self.hits += 1
                return payload.get("data")
            else:
                cache_path.unlink(missing_ok=True)
                self.misses += 1
                return None
                
        except Exception as e:
            logger.debug(f"Cache get error for {url}: {e}")
            self.misses += 1
            return None
    
    def set(self, url: str, data: Any, method: str = "GET", body: Optional[Any] = None):
        """Set cached data"""
        key = self._get_cache_key(url, method, body)
        cache_path = self._get_cache_path(key)
        
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),            "data": data,
            "url": url
        }
        
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(payload, f, separators=(',', ':'))
        except Exception as e:
            logger.debug(f"Cache set error for {url}: {e}")
    
    def clear_expired(self):
        """Clear expired cache entries"""
        cleared = 0
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r') as f:
                        payload = json.load(f)
                    
                    timestamp = datetime.fromisoformat(payload.get("timestamp", ""))
                    if datetime.now(UTC) - timestamp >= self.cache_duration:
                        cache_file.unlink()
                        cleared += 1
                except Exception:
                    cache_file.unlink(missing_ok=True)
                    cleared += 1
            
            if cleared > 0:
                logger.info(f"Cleared {cleared} expired cache entries")
        except Exception as e:
            logger.warning(f"Error clearing cache: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            files = list(self.cache_dir.glob("*.json"))
            total_size = sum(f.stat().st_size for f in files)
            hit_rate = (self.hits / (self.hits + self.misses)) * 100 if (self.hits + self.misses) > 0 else 0
            
            return {
                "directory": str(self.cache_dir),
                "files": len(files),
                "total_size_mb": total_size / (1024 * 1024),
                "hit_rate": hit_rate,
                "hits": self.hits,
                "misses": self.misses
            }
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {"error": str(e)}

class AsyncHTTPClient:
    """Async HTTP client for better performance"""
    
    def __init__(self, cache_manager: CacheManager, config: Config):
        self.cache = cache_manager
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.api_calls = 0
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=self.config.max_concurrent_requests)
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        headers = {"User-Agent": USER_AGENT}
        
        if self.config.github_token:
            headers["Authorization"] = f"token {self.config.github_token}"
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def make_request(self, url: str, method: str = "GET", json_data: Optional[dict] = None, params: Optional[dict] = None) -> Optional[dict]:
        """Make async HTTP request with caching"""
        cache_body = json_data if method.upper() == "POST" else params
        cached = self.cache.get(url, method, cache_body)
        if cached is not None:
            return cached
        
        if not self.session:
            raise RuntimeError("HTTP client not initialized. Use async context manager.")
        
        try:
            self.api_calls += 1
            async with self.session.request(method, url, json=json_data, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    self.cache.set(url, data, method, cache_body)
                    return data
                else:
                    logger.debug(f"HTTP {response.status} for {url}")
                    return None
        except Exception as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None

class HTTPClient:
    """Synchronous HTTP client with retry logic"""
    
    def __init__(self, cache_manager: CacheManager, config: Config):
        self.cache = cache_manager
        self.config = config
        self.session = self._create_session()
        self.api_calls = 0
    
    def _create_session(self) -> requests.Session:
        """Create session with retry logic"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"])
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        session.headers.update({"User-Agent": USER_AGENT})
        if self.config.github_token:
            session.headers.update({"Authorization": f"token {self.config.github_token}"})
        
        return session
    
    def make_request(self, url: str, method: str = "GET", json_data: Optional[dict] = None, params: Optional[dict] = None) -> Optional[dict]:
        """Make HTTP request with caching"""
        cache_body = json_data if method.upper() == "POST" else params
        cached = self.cache.get(url, method, cache_body)
        if cached is not None:
            return cached
        
        try:
            self.api_calls += 1
            if method.upper() == "POST":
                response = self.session.post(url, json=json_data, timeout=self.config.request_timeout)
            else:
                response = self.session.get(url, params=params, timeout=self.config.request_timeout)
            
            response.raise_for_status()
            data = response.json()
            self.cache.set(url, data, method, cache_body)
            return data
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.debug(f"JSON decode failed for {url}: {e}")
            return None

class SupplyChainAnalyzer:
    """Detect supply chain attacks and suspicious packages"""
    
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
    
    def analyze_package(self, package_name: str, package_manager: str) -> Dict[str, Any]:
        """Comprehensive supply chain analysis"""
        analysis = {
            "typosquatting_risk": self._check_typosquatting(package_name, package_manager),
            "suspicious_patterns": self._check_suspicious_patterns(package_name),
            "maintainer_analysis": self._analyze_maintainers(package_name, package_manager),
            "domain_analysis": self._analyze_domains(package_name, package_manager),
            "overall_risk": "LOW"
        }
        
        # Calculate overall risk
        risk_factors = 0
        if analysis["typosquatting_risk"]["risk_level"] != "LOW":
            risk_factors += 1
        if analysis["suspicious_patterns"]["high_risk_patterns"]:
            risk_factors += 1
        if analysis["maintainer_analysis"]["risk_indicators"]:
            risk_factors += 1
        if analysis["domain_analysis"]["suspicious_domains"]:
            risk_factors += 1
        
        if risk_factors >= 3:
            analysis["overall_risk"] = "CRITICAL"
        elif risk_factors >= 2:
            analysis["overall_risk"] = "HIGH"
        elif risk_factors >= 1:
            analysis["overall_risk"] = "MEDIUM"
        
        return analysis
    
    def _check_typosquatting(self, package_name: str, package_manager: str) -> Dict[str, Any]:
        """Check for potential typosquatting"""
        # Common popular packages to check against
        popular_packages = {
            "npm": ["lodash", "react", "axios", "express", "moment", "jquery", "webpack", "babel"],
            "pypi": ["requests", "numpy", "pandas", "django", "flask", "pillow", "pytest", "matplotlib"],
            "cargo": ["serde", "tokio", "clap", "regex", "rand", "log", "syn", "quote"],
            "maven": ["junit", "slf4j", "jackson", "spring", "gson", "guava", "commons", "mockito"]
        }
        
        similar_packages = []
        pm_packages = popular_packages.get(package_manager.lower(), [])
        
        for popular in pm_packages:
            similarity = difflib.SequenceMatcher(None, package_name.lower(), popular.lower()).ratio()
            if 0.7 <= similarity < 1.0:  # Similar but not exact
                similar_packages.append({
                    "package": popular,
                    "similarity": similarity,
                    "potential_typosquat": True
                })
        
        # Check for common typosquatting patterns
        risk_patterns = []
        for popular in pm_packages:
            if package_name.lower() != popular.lower():
                # Character substitution
                if self._levenshtein_distance(package_name.lower(), popular.lower()) == 1:
                    risk_patterns.append(f"Single character difference from '{popular}'")
                
                # Common substitutions
                substitutions = {
                    'o': '0', 'i': '1', 'l': '1', 'e': '3', 's': '5',
                    '0': 'o', '1': 'i', '1': 'l', '3': 'e', '5': 's'
                }
                
                for char, sub in substitutions.items():
                    if popular.replace(char, sub) == package_name.lower():
                        risk_patterns.append(f"Character substitution from '{popular}' ({char}→{sub})")
        
        risk_level = "LOW"
        if len(similar_packages) > 0 or len(risk_patterns) > 0:
            risk_level = "HIGH"
        
        return {
            "similar_packages": similar_packages,
            "risk_patterns": risk_patterns,
            "risk_level": risk_level
        }
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _check_suspicious_patterns(self, package_name: str) -> Dict[str, Any]:
        """Check for suspicious naming patterns"""
        suspicious_patterns = []
        high_risk_patterns = []
        
        # Pattern checks
        if any(keyword in package_name.lower() for keyword in ["test", "temp", "tmp", "demo", "sample"]):
            suspicious_patterns.append("Contains test/temporary keywords")
        
        if any(char in package_name for char in ["_", "-"] * 3):  # Multiple separators
            suspicious_patterns.append("Excessive use of separators")
        
        if len(package_name) > 50:
            suspicious_patterns.append("Unusually long package name")
        
        if package_name.lower() != package_name and package_name.upper() != package_name:
            # Mixed case in unusual patterns
            if sum(1 for c in package_name if c.isupper()) > len(package_name) * 0.3:
                high_risk_patterns.append("Unusual capitalization pattern")
        
        # Homograph attacks (basic check)
        suspicious_chars = ['0', '1', '3', '5']
        if any(char in package_name for char in suspicious_chars):
            suspicious_patterns.append("Contains potentially confusing characters")
        
        return {
            "suspicious_patterns": suspicious_patterns,
            "high_risk_patterns": high_risk_patterns
        }
    
    def _analyze_maintainers(self, package_name: str, package_manager: str) -> Dict[str, Any]:
        """Analyze package maintainers for risk indicators"""
        # This would require more detailed package registry API calls
        # For now, return basic structure
        return {
            "risk_indicators": [],
            "maintainer_count": 0,
            "new_maintainers": False
        }
    
    def _analyze_domains(self, package_name: str, package_manager: str) -> Dict[str, Any]:
        """Analyze domains associated with the package"""
        # This would check homepage, repository URLs, etc. for suspicious domains
        return {
            "suspicious_domains": [],
            "domain_reputation": "UNKNOWN"
        }

class SBOMAnalyzer:
    """Software Bill of Materials analysis"""
    
    def __init__(self, http_client: HTTPClient, config: Config):
        self.http_client = http_client
        self.config = config
    
    async def analyze_dependencies(self, package_name: str, package_manager: str, version: Optional[str] = None) -> Dict[str, Any]:
        """Analyze package dependencies and create SBOM"""
        if not self.config.enable_sbom:
            return {"message": "SBOM analysis disabled in configuration"}
        
        try:
            dependencies = await self._fetch_dependencies(package_name, package_manager, version)
            sbom = self._create_sbom(package_name, package_manager, version, dependencies)
            risk_analysis = self._analyze_dependency_risks(dependencies)
            
            return {
                "sbom": sbom,
                "dependency_count": len(dependencies),
                "risk_analysis": risk_analysis,
                "recommendations": self._generate_sbom_recommendations(risk_analysis)
            }
        except Exception as e:
            logger.error(f"SBOM analysis failed for {package_name}: {e}")
            return {"error": f"SBOM analysis failed: {e}"}
    
    async def _fetch_dependencies(self, package_name: str, package_manager: str, version: Optional[str] = None) -> List[Dict]:
        """Fetch package dependencies"""
        dependencies = []
        
        if package_manager.lower() == "npm":
            dependencies = await self._fetch_npm_dependencies(package_name, version)
        elif package_manager.lower() == "pypi":
            dependencies = await self._fetch_pypi_dependencies(package_name, version)
        elif package_manager.lower() == "maven":
            dependencies = await self._fetch_maven_dependencies(package_name, version)
        
        return dependencies
    
    async def _fetch_npm_dependencies(self, package_name: str, version: Optional[str] = None) -> List[Dict]:
        """Fetch npm dependencies"""
        try:
            url = f"https://registry.npmjs.org/{package_name}"
            data = self.http_client.make_request(url)
            if not data:
                return []
            
            # Get dependencies from latest version or specified version
            target_version = version or data.get("dist-tags", {}).get("latest")
            versions = data.get("versions", {})
            
            if target_version in versions:
                deps = versions[target_version].get("dependencies", {})
                return [{"name": name, "version": ver, "type": "dependency"} for name, ver in deps.items()]
        except Exception as e:
            logger.debug(f"Failed to fetch npm dependencies for {package_name}: {e}")
        
        return []
    
    async def _fetch_pypi_dependencies(self, package_name: str, version: Optional[str] = None) -> List[Dict]:
        """Fetch PyPI dependencies"""
        # PyPI doesn't provide detailed dependency info in JSON API
        # Would need to parse setup.py or requirements files
        return []
    
    async def _fetch_maven_dependencies(self, package_name: str, version: Optional[str] = None) -> List[Dict]:
        """Fetch Maven dependencies"""
        # Would need to parse POM files from Maven Central
        return []
    
    def _create_sbom(self, package_name: str, package_manager: str, version: Optional[str], dependencies: List[Dict]) -> Dict:
        """Create Software Bill of Materials"""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [{"name": "OpenSSF-Evaluator", "version": "3.0"}]
            },
            "components": [
                {
                    "type": "library",
                    "name": package_name,
                    "version": version or "latest",
                    "purl": f"pkg:{package_manager}/{package_name}@{version or 'latest'}"
                }
            ] + [
                {
                    "type": "library",
                    "name": dep["name"],
                    "version": dep["version"],
                    "purl": f"pkg:{package_manager}/{dep['name']}@{dep['version']}"
                } for dep in dependencies
            ]
        }
    
    def _analyze_dependency_risks(self, dependencies: List[Dict]) -> Dict[str, Any]:
        """Analyze risks in dependencies"""
        return {
            "total_dependencies": len(dependencies),
            "high_risk_dependencies": 0,
            "outdated_dependencies": 0,
            "vulnerable_dependencies": 0,
            "license_issues": 0
        }
    
    def _generate_sbom_recommendations(self, risk_analysis: Dict) -> List[str]:
        """Generate SBOM-based recommendations"""
        recommendations = []
        
        if risk_analysis["total_dependencies"] > 100:
            recommendations.append("⚠️ Large dependency tree - consider reducing dependencies")
        
        if risk_analysis["high_risk_dependencies"] > 0:
            recommendations.append("🚨 High-risk dependencies detected - review and consider alternatives")
        
        return recommendations

class EnhancedVulnerabilityScanner:
    """Enhanced vulnerability scanner with additional features"""
    
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.ecosystem_map = {
            "npm": "npm", "pypi": "PyPI", "maven": "Maven", "gradle": "Maven",
            "cargo": "crates.io", "nuget": "NuGet", "rubygems": "RubyGems",
            "composer": "Packagist", "go": "Go", "pub": "Pub", "cocoapods": "CocoaPods",
            "swift": "SwiftURL", "hex": "Hex", "cran": "CRAN"
        }
    
    def scan_package(self, package_name: str, package_manager: str, version: Optional[str] = None) -> Dict[str, Any]:
        """Enhanced vulnerability scanning"""
        ecosystem = self.ecosystem_map.get(package_manager.lower())
        if not ecosystem:
            return {
                "total_vulnerabilities": 0,
                "vulnerabilities": [],
                "recommendation": f"Vulnerability scanning not available for {package_manager}"
            }
        
        try:
            query_data = {"package": {"name": package_name, "ecosystem": ecosystem}}
            if version:
                query_data["version"] = version
            
            response = self.http_client.make_request(OSV_API_URL, method="POST", json_data=query_data)
            if not response:
                return {
                    "total_vulnerabilities": 0,
                    "vulnerabilities": [],
                    "recommendation": "No vulnerability data available"
                }
            
            vulnerabilities = self._process_vulnerabilities(response.get("vulns", []))
            analysis = self._analyze_vulnerabilities(vulnerabilities)
            
            # Add EPSS scores if available
            self._enrich_with_epss(analysis["vulnerabilities"])
            
            return analysis
            
        except Exception as e:
            logger.error(f"Vulnerability scan failed for {package_name}: {e}")
            return {
                "total_vulnerabilities": 0,
                "vulnerabilities": [],
                "recommendation": f"Vulnerability scan failed: {e}"
            }
    
    def _process_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """Process raw vulnerability data"""
        processed = []
        for vuln in vulns:
            processed.append({
                "id": vuln.get("id", ""),
                "summary": vuln.get("summary") or vuln.get("details", "No summary available"),
                "severity": self._extract_severity(vuln),
                "published": vuln.get("published", ""),
                "modified": vuln.get("modified", ""),
                "database_specific": vuln.get("database_specific", {}),
                "references": vuln.get("references", [])
            })
        return processed
    
    def _extract_severity(self, vuln: Dict) -> str:
        """Extract and normalize severity"""
        severity = vuln.get("severity")
        if isinstance(severity, list) and severity:
            for sev_item in severity:
                if isinstance(sev_item, dict) and "score" in sev_item:
                    return str(sev_item["score"]).upper()
        elif isinstance(severity, str):
            return severity.upper()
        
        # Check database_specific for CVSS
        db_specific = vuln.get("database_specific", {})
        if "cvss" in db_specific:
            cvss_data = db_specific["cvss"]
            if isinstance(cvss_data, list) and cvss_data:
                return str(cvss_data[0].get("score", "UNKNOWN")).upper()
        
        return "UNKNOWN"
    
    def _analyze_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Enhanced vulnerability analysis"""
        if not vulnerabilities:
            return {
                "total_vulnerabilities": 0,
                "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "vulnerabilities": [],
                "recommendation": "✅ No known vulnerabilities found",
                "epss_analysis": {"average_epss": 0, "high_exploit_risk": 0}
            }
        
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for vuln in vulnerabilities:
            severity = self._normalize_severity(vuln["severity"])
            severity_breakdown[severity] += 1
            vuln["normalized_severity"] = severity
        
        recommendation = self._generate_vulnerability_recommendation(severity_breakdown)
        
        return {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": severity_breakdown,
            "vulnerabilities": vulnerabilities[:10],  # Limit display
            "recommendation": recommendation,
            "epss_analysis": {"average_epss": 0, "high_exploit_risk": 0}
        }
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to standard levels"""
        severity = severity.upper()
        
        try:
            score = float(severity)
            if score >= 9.0:
                return "CRITICAL"
            elif score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"
        except ValueError:
            if "CRITICAL" in severity:
                return "CRITICAL"
            elif "HIGH" in severity:
                return "HIGH"
            elif "MEDIUM" in severity:
                return "MEDIUM"
            else:
                return "LOW"
    
    def _generate_vulnerability_recommendation(self, severity_breakdown: Dict) -> str:
        """Generate vulnerability-based recommendations"""
        if severity_breakdown["CRITICAL"] > 0:
            return "🚨 CRITICAL vulnerabilities found - immediate action required"
        elif severity_breakdown["HIGH"] > 0:
            return "⚠️ HIGH severity vulnerabilities found - update urgently"
        elif severity_breakdown["MEDIUM"] > 0:
            return "⚠️ MEDIUM severity vulnerabilities found - plan updates"
        elif severity_breakdown["LOW"] > 0:
            return "⚠️ LOW severity vulnerabilities found - monitor updates"
        else:
            return "✅ No known vulnerabilities found"
    
    def _enrich_with_epss(self, vulnerabilities: List[Dict]):
        """Enrich vulnerabilities with EPSS scores (placeholder)"""
        # EPSS (Exploit Prediction Scoring System) integration would go here
        for vuln in vulnerabilities:
            vuln["epss_score"] = 0.0  # Placeholder
            vuln["exploit_likelihood"] = "LOW"  # Placeholder

class EnhancedAlternativeFinder:
    """Enhanced alternative finder with better ranking and compatibility analysis"""
    
    def __init__(self, http_client: HTTPClient, config: Config):
        self.http_client = http_client
        self.config = config
        
        # Enhanced alternative patterns
        self.alternative_patterns = {
            "npm": {
                'lodash': ['underscore', 'ramda', 'lazy.js', 'rambda'],
                'moment': ['dayjs', 'date-fns', 'luxon', 'js-joda'],
                'jquery': ['zepto', 'cash-dom', 'umbrella', 'vanilla-js'],
                'express': ['koa', 'fastify', 'hapi', 'restify'],
                'react': ['vue', 'angular', 'svelte', 'preact'],
                'axios': ['fetch', 'got', 'node-fetch', 'superagent'],
                'webpack': ['rollup', 'parcel', 'vite', 'esbuild'],
                'babel': ['typescript', 'swc', 'esbuild', 'sucrase']
            },
            "pypi": {
                'requests': ['httpx', 'urllib3', 'aiohttp', 'httpcore'],
                'django': ['flask', 'fastapi', 'tornado', 'bottle'],
                'pandas': ['polars', 'dask', 'modin', 'vaex'],
                'numpy': ['cupy', 'jax', 'torch', 'tensorflow'],
                'matplotlib': ['plotly', 'seaborn', 'bokeh', 'altair'],
                'pytest': ['unittest', 'nose2', 'doctest', 'hypothesis'],
                'pillow': ['opencv-python', 'imageio', 'scikit-image', 'wand']
            },
            "maven": {
                'junit': ['testng', 'spock', 'assertj', 'mockito'],
                'log4j': ['logback', 'slf4j', 'java-util-logging', 'tinylog'],
                'jackson': ['gson', 'moshi', 'fastjson', 'jsonb'],
                'spring': ['quarkus', 'micronaut', 'vert.x', 'dropwizard'],
                'hibernate': ['jpa', 'mybatis', 'jooq', 'ebean'],
                'guava': ['apache-commons', 'eclipse-collections', 'vavr', 'caffeine']
            },
            "cargo": {
                'serde': ['bincode', 'postcard', 'rmp-serde', 'ron'],
                'tokio': ['async-std', 'smol', 'futures', 'actix'],
                'reqwest': ['surf', 'isahc', 'ureq', 'hyper'],
                'clap': ['structopt', 'argh', 'pico-args', 'gumdrop'],
                'regex': ['fancy-regex', 'onig', 'pcre2', 'aho-corasick']
            }
        }
    
    async def find_alternatives(self, package_name: str, package_manager: str, max_alternatives: int = None) -> List[Dict]:
        """Find alternatives with enhanced ranking"""
        max_alternatives = max_alternatives or self.config.max_alternatives
        
        # Get original package info for compatibility analysis
        original_package = await self._get_package_info(package_name, package_manager)
        
        # Find alternatives using multiple strategies
        alternatives = []
        alternatives.extend(await self._get_predefined_alternatives(package_name, package_manager))
        alternatives.extend(await self._search_similar_packages(package_name, package_manager, original_package))
        
        # Remove duplicates and original package
        seen = {package_name.lower()}
        unique_alternatives = []
        for alt in alternatives:
            if alt["name"].lower() not in seen:
                seen.add(alt["name"].lower())
                unique_alternatives.append(alt)
        
        # Enhanced ranking
        ranked_alternatives = await self._enhanced_rank_alternatives(unique_alternatives, original_package)
        
        return ranked_alternatives[:max_alternatives]
    
    async def _get_package_info(self, package_name: str, package_manager: str) -> Dict:
        """Get detailed package information"""
        try:
            if package_manager.lower() == "npm":
                url = f"https://registry.npmjs.org/{package_name}"
                data = self.http_client.make_request(url)
                if data:
                    return {
                        "name": package_name,
                        "description": data.get("description", ""),
                        "keywords": data.get("keywords", []),
                        "repository": data.get("repository", {}),
                        "license": data.get("license", ""),
                        "downloads": 0  # Would need separate API call
                    }
            elif package_manager.lower() == "pypi":
                url = f"https://pypi.org/pypi/{package_name}/json"
                data = self.http_client.make_request(url)
                if data:
                    info = data.get("info", {})
                    return {
                        "name": package_name,
                        "description": info.get("summary", ""),
                        "keywords": info.get("keywords", "").split(",") if info.get("keywords") else [],
                        "classifiers": info.get("classifiers", []),
                        "license": info.get("license", ""),
                        "downloads": 0
                    }
        except Exception as e:
            logger.debug(f"Failed to get package info for {package_name}: {e}")
        
        return {"name": package_name}
    
    async def _get_predefined_alternatives(self, package_name: str, package_manager: str) -> List[Dict]:
        """Get predefined alternatives"""
        alternatives = []
        patterns = self.alternative_patterns.get(package_manager.lower(), {})
        
        if package_name.lower() in patterns:
            for alt_name in patterns[package_name.lower()]:
                alt_info = await self._quick_evaluate_alternative(alt_name, package_manager)
                if alt_info:
                    alternatives.append(alt_info)
        
        return alternatives
    
    async def _search_similar_packages(self, package_name: str, package_manager: str, original_package: Dict) -> List[Dict]:
        """Search for similar packages"""
        alternatives = []
        
        try:
            if package_manager.lower() == "npm":
                # Search by keywords
                keywords = original_package.get("keywords", [])
                for keyword in keywords[:3]:
                    if keyword:
                        url = f"https://registry.npmjs.org/-/v1/search?text={quote(keyword)}&size=10"
                        data = self.http_client.make_request(url)
                        if data:
                            for obj in data.get("objects", []):
                                pkg = obj.get("package", {})
                                if pkg.get("name") and pkg["name"] != package_name:
                                    alt_info = self._process_npm_search_result(obj)
                                    if alt_info:
                                        alternatives.append(alt_info)
            
            elif package_manager.lower() == "cargo":
                # Use crates.io search
                description = original_package.get("description", "")
                search_terms = description.split()[:3]  # First 3 words
                for term in search_terms:
                    if len(term) > 3:
                        url = f"https://crates.io/api/v1/crates?q={quote(term)}&per_page=10"
                        data = self.http_client.make_request(url)
                        if data:
                            for crate in data.get("crates", []):
                                if crate.get("name") and crate["name"] != package_name:
                                    alt_info = self._process_cargo_search_result(crate)
                                    if alt_info:
                                        alternatives.append(alt_info)
        
        except Exception as e:
            logger.debug(f"Search for similar packages failed: {e}")
        
        return alternatives
    
    async def _quick_evaluate_alternative(self, package_name: str, package_manager: str) -> Optional[Dict]:
        """Quick evaluation of an alternative package"""
        try:
            if package_manager.lower() == "npm":
                url = f"https://registry.npmjs.org/{package_name}"
                data = self.http_client.make_request(url)
                if data:
                    return {
                        "name": package_name,
                        "version": data.get("dist-tags", {}).get("latest", "unknown"),
                        "description": data.get("description", "No description"),
                        "score": 50,  # Base score
                        "registry_url": f"https://www.npmjs.com/package/{package_name}",
                        "manager": "npm",
                        "license": data.get("license", ""),
                        "repository": data.get("repository", {})
                    }
            
            elif package_manager.lower() == "pypi":
                url = f"https://pypi.org/pypi/{package_name}/json"
                data = self.http_client.make_request(url)
                if data:
                    info = data.get("info", {})
                    return {
                        "name": package_name,
                        "version": info.get("version", "unknown"),
                        "description": info.get("summary", "No description"),
                        "score": 50,
                        "registry_url": f"https://pypi.org/project/{package_name}/",
                        "manager": "pypi",
                        "license": info.get("license", ""),
                        "home_page": info.get("home_page", "")
                    }
            
            elif package_manager.lower() == "cargo":
                url = f"https://crates.io/api/v1/crates/{package_name}"
                data = self.http_client.make_request(url)
                if data:
                    crate = data.get("crate", {})
                    return {
                        "name": package_name,
                        "version": crate.get("newest_version", "unknown"),
                        "description": crate.get("description", "No description"),
                        "score": 50,
                        "registry_url": f"https://crates.io/crates/{package_name}",
                        "manager": "cargo",
                        "downloads": crate.get("downloads", 0),
                        "repository": crate.get("repository", "")
                    }
        
        except Exception as e:
            logger.debug(f"Quick evaluation failed for {package_name}: {e}")
        
        return None
    
    def _process_npm_search_result(self, search_result: Dict) -> Optional[Dict]:
        """Process npm search result"""
        try:
            pkg = search_result.get("package", {})
            score_data = search_result.get("score", {})
            
            return {
                "name": pkg.get("name", ""),
                "version": pkg.get("version", "unknown"),
                "description": pkg.get("description", "No description"),
                "score": score_data.get("final", 0) * 100,
                "registry_url": f"https://www.npmjs.com/package/{pkg.get('name', '')}",
                "manager": "npm",
                "npm_score": score_data
            }
        except Exception:
            return None
    
    def _process_cargo_search_result(self, crate_data: Dict) -> Optional[Dict]:
        """Process cargo search result"""
        try:
            downloads = crate_data.get("downloads", 0)
            recent_downloads = crate_data.get("recent_downloads", 0)
            
            # Simple scoring based on downloads
            score = min(100, (downloads / 100000) * 50 + (recent_downloads / 10000) * 50)
            
            return {
                "name": crate_data.get("name", ""),
                "version": crate_data.get("newest_version", "unknown"),
                "description": crate_data.get("description", "No description"),
                "score": score,
                "registry_url": f"https://crates.io/crates/{crate_data.get('name', '')}",
                "manager": "cargo",
                "downloads": downloads
            }
        except Exception:
            return None
    
    async def _enhanced_rank_alternatives(self, alternatives: List[Dict], original_package: Dict) -> List[Dict]:
        """Enhanced ranking with multiple factors"""
        for alt in alternatives:
            # Calculate component scores
            alt["compatibility_score"] = self._calculate_compatibility_score(alt, original_package)
            alt["security_score"] = await self._calculate_security_score(alt)
            alt["maintenance_score"] = self._calculate_maintenance_score(alt)
            alt["popularity_score"] = self._calculate_popularity_score(alt)
            
            # Weighted final score
            weights = {
                "base_score": 0.25,
                "compatibility": 0.25,
                "security": 0.25,
                "maintenance": 0.15,
                "popularity": 0.10
            }
            
            alt["final_score"] = (
                alt.get("score", 0) * weights["base_score"] +
                alt["compatibility_score"] * weights["compatibility"] +
                alt["security_score"] * weights["security"] +
                alt["maintenance_score"] * weights["maintenance"] +
                alt["popularity_score"] * weights["popularity"]
            )
        
        return sorted(alternatives, key=lambda x: x.get("final_score", 0), reverse=True)
    
    def _calculate_compatibility_score(self, alternative: Dict, original: Dict) -> float:
        """Calculate compatibility score between packages"""
        score = 50.0  # Base compatibility score
        
        # Check description similarity
        alt_desc = alternative.get("description", "").lower()
        orig_desc = original.get("description", "").lower()
        
        if alt_desc and orig_desc:
            # Simple word overlap
            alt_words = set(alt_desc.split())
            orig_words = set(orig_desc.split())
            overlap = len(alt_words.intersection(orig_words))
            total_words = len(alt_words.union(orig_words))
            
            if total_words > 0:
                similarity = (overlap / total_words) * 100
                score += similarity * 0.5
        
        # Check license compatibility
        alt_license = alternative.get("license", "").lower()
        orig_license = original.get("license", "").lower()
        
        if alt_license and orig_license:
            if alt_license == orig_license:
                score += 20
            elif any(lic in alt_license for lic in ["mit", "apache", "bsd"]) and any(lic in orig_license for lic in ["mit", "apache", "bsd"]):
                score += 10
        
        return min(100.0, score)
    
    async def _calculate_security_score(self, alternative: Dict) -> float:
        """Calculate security score for alternative"""
        score = 50.0  # Base security score
        
        # Would integrate with vulnerability scanner here
        # For now, return base score
        return score
    
    def _calculate_maintenance_score(self, alternative: Dict) -> float:
        """Calculate maintenance score"""
        score = 50.0  # Base maintenance score
        
        # Check if it has a repository
        if alternative.get("repository"):
            score += 20
        
        # Check version (newer versions might indicate active maintenance)
        version = alternative.get("version", "")
        if version and version != "unknown":
            # Simple heuristic: if version is > 1.0, add points
            try:
                major_version = float(version.split(".")[0])
                if major_version >= 1.0:
                    score += 15
            except (ValueError, IndexError):
                pass
        
        return min(100.0, score)
    
    def _calculate_popularity_score(self, alternative: Dict) -> float:
        """Calculate popularity score"""
        score = 0.0
        
        # Downloads-based scoring
        downloads = alternative.get("downloads", 0)
        if downloads > 0:
            score = min(100.0, (downloads / 1000000) * 100)
        
        # npm-specific scoring
        npm_score = alternative.get("npm_score", {})
        if npm_score:
            popularity = npm_score.get("detail", {}).get("popularity", 0)
            score = max(score, popularity * 100)
        
        return score

class MultiPackageManagerEvaluator:
    """Enhanced package evaluator supporting multiple package managers"""
    
    def __init__(self, http_client: HTTPClient, config: Config):
        self.http_client = http_client
        self.config = config
        self.vuln_scanner = EnhancedVulnerabilityScanner(http_client)
        self.sbom_analyzer = SBOMAnalyzer(http_client, config)
        self.supply_chain_analyzer = SupplyChainAnalyzer(http_client)
        
        # Package manager configurations
        self.package_managers = {
            "npm": {
                "registry_url": "https://registry.npmjs.org",
                "package_url_template": "https://www.npmjs.com/package/{name}",
                "api_docs": "https://github.com/npm/registry/blob/master/docs/REGISTRY-API.md"
            },
            "pypi": {
                "registry_url": "https://pypi.org/pypi",
                "package_url_template": "https://pypi.org/project/{name}/",
                "api_docs": "https://warehouse.readthedocs.io/api-reference/"
            },
            "cargo": {
                "registry_url": "https://crates.io/api/v1/crates",
                "package_url_template": "https://crates.io/crates/{name}",
                "api_docs": "https://doc.rust-lang.org/cargo/reference/registries.html"
            },
            "maven": {
                "registry_url": "https://search.maven.org/solrsearch/select",
                "package_url_template": "https://mvnrepository.com/artifact/{group}/{name}",
                "api_docs": "https://central.sonatype.org/search/rest-api-guide/"
            },
            "nuget": {
                "registry_url": "https://api.nuget.org/v3/registration3",
                "package_url_template": "https://www.nuget.org/packages/{name}",
                "api_docs": "https://docs.microsoft.com/en-us/nuget/api/overview"
            },
            "rubygems": {
                "registry_url": "https://rubygems.org/api/v1/gems",
                "package_url_template": "https://rubygems.org/gems/{name}",
                "api_docs": "https://guides.rubygems.org/rubygems-org-api/"
            },
            "go": {
                "registry_url": "https://proxy.golang.org",
                "package_url_template": "https://pkg.go.dev/{name}",
                "api_docs": "https://go.dev/ref/mod#goproxy-protocol"
            }
        }
    
    async def evaluate_package(self, package_name: str, package_manager: str = "npm", version: Optional[str] = None) -> Dict[str, Any]:
        """Comprehensive package evaluation with all features"""
        start_time = time.time()
        pm = package_manager.lower()
        
        if pm not in self.package_managers:
            return {"error": f"Package manager '{package_manager}' not supported"}
        
        try:
            # Core package evaluation
            evaluation = await self._evaluate_package_core(package_name, pm, version)
            if "error" in evaluation:
                return evaluation
            
            # Vulnerability scanning (now included by default)
            vuln_results = self.vuln_scanner.scan_package(package_name, pm, version)
            evaluation["vulnerability_analysis"] = vuln_results
            
            # Supply chain analysis
            if self.config.enable_supply_chain_checks:
                supply_chain_results = self.supply_chain_analyzer.analyze_package(package_name, pm)
                evaluation["supply_chain_analysis"] = supply_chain_results
            
            # SBOM analysis
            if self.config.enable_sbom:
                sbom_results = await self.sbom_analyzer.analyze_dependencies(package_name, pm, version)
                evaluation["sbom_analysis"] = sbom_results
            
            # Calculate comprehensive score
            evaluation["openssf_score"] = self._calculate_comprehensive_score(evaluation)
            evaluation["recommendations"] = self._generate_comprehensive_recommendations(evaluation)
            evaluation["needs_alternatives"] = self._needs_alternatives(evaluation)
            
            # Record metrics
            duration = time.time() - start_time
            self._record_evaluation_metrics(evaluation, duration)
            
            return evaluation
            
        except Exception as e:
            logger.exception(f"Evaluation failed for {package_name} ({package_manager})")
            return {"error": f"Evaluation failed: {e}"}
    
    async def _evaluate_package_core(self, package_name: str, package_manager: str, version: Optional[str] = None) -> Dict[str, Any]:
        """Core package evaluation logic"""
        if package_manager == "npm":
            return await self._evaluate_npm_package(package_name, version)
        elif package_manager == "pypi":
            return await self._evaluate_pypi_package(package_name, version)
        elif package_manager == "cargo":
            return await self._evaluate_cargo_package(package_name, version)
        elif package_manager == "maven":
            return await self._evaluate_maven_package(package_name, version)
        elif package_manager == "nuget":
            return await self._evaluate_nuget_package(package_name, version)
        elif package_manager == "rubygems":
            return await self._evaluate_rubygems_package(package_name, version)
        elif package_manager == "go":
            return await self._evaluate_go_package(package_name, version)
        else:
            return {"error": f"Package manager '{package_manager}' not implemented yet"}
    
    async def _evaluate_npm_package(self, package_name: str, version: Optional[str] = None) -> Dict[str, Any]:
        """Evaluate npm package"""
        try:
            url = f"https://registry.npmjs.org/{package_name}"
            data = self.http_client.make_request(url)
            if not data:
                return {"error": f"NPM package '{package_name}' not found"}
            
            target_version = version or data.get("dist-tags", {}).get("latest", "unknown")
            description = data.get("description", "No description")
            repository = data.get("repository", {})
            github_url = self._extract_github_url(repository)
            
            evaluation = {
                "package_name": package_name,
                "package_manager": "npm",
                "target_version": target_version,
                "latest_version": data.get("dist-tags", {}).get("latest", "unknown"),
                "description": description,
                "repository_url": github_url,
                "registry_url": f"https://www.npmjs.com/package/{package_name}",
                "evaluation_date": datetime.now(UTC).isoformat(),
                "license": data.get("license", "No license"),
                "keywords": data.get("keywords", [])
            }
            
            # Get download stats
            downloads_url = f"https://api.npmjs.org/downloads/point/last-week/{package_name}"
            downloads_data = self.http_client.make_request(downloads_url)
            if downloads_data:
                evaluation["weekly_downloads"] = downloads_data.get("downloads", 0)
            
            # GitHub analysis
            if github_url:
                github_analysis = await self._analyze_github_repo(github_url)
                evaluation.update(github_analysis)
            
            return evaluation
            
        except Exception as e:
            return {"error": f"Failed to evaluate npm package: {e}"}
    
    async def _evaluate_pypi_package(self, package_name: str, version: Optional[str] = None) -> Dict[str, Any]:
        """Evaluate PyPI package"""
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            data = self.http_client.make_request(url)
            if not data:
                return {"error": f"PyPI package '{package_name}' not found"}
            
            info = data.get("info", {})
            target_version = version or info.get("version", "unknown")
            
            evaluation = {
                "package_name": package_name,
                "package_manager": "pypi",
                "target_version": target_version,
                "latest_version": info.get("version", "unknown"),
                "description": info.get("summary", "No description"),
                "repository_url": self._find_github_in_urls(info.get("project_urls", {})),
                "registry_url": f"https://pypi.org/project/{package_name}/",
                "evaluation_date": datetime.now(UTC).isoformat(),
                "license": info.get("license", "No license"),
                "classifiers": info.get("classifiers", []),
                "author": info.get("author", "Unknown"),
                "home_page": info.get("home_page", "")
            }
            
            # GitHub analysis
            if evaluation.get("repository_url"):
                github_analysis = await self._analyze_github_repo(evaluation["repository_url"])
                evaluation.update(github_analysis)
            
            return evaluation
            
        except Exception as e:
            return {"error": f"Failed to evaluate PyPI package: {e}"}
    
    async def _evaluate_cargo_package(self, package_name: str, version: Optional[str] = None) -> Dict[str, Any]:
        """Evaluate Cargo package"""
        try:
            url = f"https://crates.io/api/v1/crates/{package_name}"
            data = self.http_client.make_request(url)
            if not data:
                return {"error": f"Cargo package '{package_name}' not found"}
            
            crate = data.get("crate", {})
            target_version = version or crate.get("newest_version", "unknown")
            
            evaluation = {
                "package_name": package_name,
                "package_manager": "cargo",
                "target_version": target_version,
                "latest_version": crate.get("newest_version", "unknown"),
                "description": crate.get("description", "No description"),
                "repository_url": crate.get("repository", ""),
                "registry_url": f"https://crates.io/crates/{package_name}",
                "evaluation_date": datetime.now(UTC).isoformat(),
                "downloads": crate.get("downloads", 0),
                "recent_downloads": crate.get("recent_downloads", 0),
                "keywords": crate.get("keywords", []),
                "categories": crate.get("categories", [])
            }
            
            # GitHub analysis
            if evaluation.get("repository_url") and "github.com" in evaluation["repository_url"]:
                github_analysis = await self._analyze_github_repo(evaluation["repository_url"])
                evaluation.update(github_analysis)
            
            return evaluation
            
        except Exception as e:
            return {"error": f"Failed to evaluate Cargo package: {e}"}
    
    async def _evaluate_maven_package(self, package_name: str, version: Optional[str] = None) -> Dict[str, Any]:
        """Evaluate Maven package"""
        try:
            # Maven packages have group:artifact format
            if ":" in package_name:
                group_id, artifact_id = package_name.split(":", 1)
            else:
                # Assume common group pattern
                group_id = f"org.{package_name}"
                artifact_id = package_name
            
            # Search Maven Central
            search_url = f"https://search.maven.org/solrsearch/select"
            params = {
                "q": f"g:{group_id} AND a:{artifact_id}",
                "rows": 1,
                "wt": "json"
            }
            
            data = self.http_client.make_request(search_url, params=params)
            if not data or not data.get("response", {}).get("docs"):
                return {"error": f"Maven package '{package_name}' not found"}
            
            doc = data["response"]["docs"][0]
            target_version = version or doc.get("latestVersion", "unknown")
            
            evaluation = {
                "package_name": package_name,
                "package_manager": "maven",
                "target_version": target_version,
                "latest_version": doc.get("latestVersion", "unknown"),
                "description": f"Maven package {group_id}:{artifact_id}",
                "registry_url": f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}",
                "evaluation_date": datetime.now(UTC).isoformat(),
                "group_id": group_id,
                "artifact_id": artifact_id,
                "packaging": doc.get("p", "jar")
            }
            
            return evaluation
            
        except Exception as e:
            return {"error": f"Failed to evaluate Maven package: {e}"}
    
    async def _evaluate_nuget_package(self, package_name: str, version: Optional[str] = None) -> Dict[str, Any]:
        """Evaluate NuGet package"""
        try:
            url = f"https://api.nuget.org/v3-flatcontainer/{package_name.lower()}/index.json"
            data = self.http_client.make_request(url)
            if not data:
                return {"error": f"NuGet package '{package_name}' not found"}
            
            versions = data.get("versions", [])
            target_version = version or (versions[-1] if versions else "unknown")
            
            evaluation = {
                "package_name": package_name,
                "package_manager": "nuget",
                "target_version": target_version,
                "latest_version": versions[-1] if versions else "unknown",
                "description": f"NuGet package {package_name}",
                "registry_url": f"https://www.nuget.org/packages/{package_name}",
                "evaluation_date": datetime.now(UTC).isoformat(),
                "available_versions": len(versions)
            }
            
            return evaluation
            
        except Exception as e:
            return {"error": f"Failed to evaluate NuGet package: {e}"}
    
    async def _evaluate_rubygems_package(self, package_name: str, version: Optional[str] = None) -> Dict[str, Any]:
        """Evaluate RubyGems package"""
        try:
            url = f"https://rubygems.org/api/v1/gems/{package_name}.json"
            data = self.http_client.make_request(url)
            if not data:
                return {"error": f"RubyGems package '{package_name}' not found"}
            
            target_version = version or data.get("version", "unknown")
            
            evaluation = {
                "package_name": package_name,
                "package_manager": "rubygems",
                "target_version": target_version,
                "latest_version": data.get("version", "unknown"),
                "description": data.get("info", "No description"),
                "repository_url": data.get("source_code_uri", ""),
                "registry_url": f"https://rubygems.org/gems/{package_name}",
                "evaluation_date": datetime.now(UTC).isoformat(),
                "downloads": data.get("downloads", 0),
                "authors": data.get("authors", "Unknown")
            }
            
            # GitHub analysis
            if evaluation.get("repository_url") and "github.com" in evaluation["repository_url"]:
                github_analysis = await self._analyze_github_repo(evaluation["repository_url"])
                evaluation.update(github_analysis)
            
            return evaluation
            
        except Exception as e:
            return {"error": f"Failed to evaluate RubyGems package: {e}"}
    
    async def _evaluate_go_package(self, package_name: str, version: Optional[str] = None) -> Dict[str, Any]:
        """Evaluate Go package"""
        try:
            # Go packages are typically identified by their import path
            # This is a simplified implementation
            evaluation = {
                "package_name": package_name,
                "package_manager": "go",
                "target_version": version or "latest",
                "latest_version": "latest",
                "description": f"Go package {package_name}",
                "registry_url": f"https://pkg.go.dev/{package_name}",
                "evaluation_date": datetime.utcnow().isoformat()
            }
            
            # If it's a GitHub-hosted package
            if "github.com" in package_name:
                github_url = f"https://{package_name}"
                github_analysis = await self._analyze_github_repo(github_url)
                evaluation.update(github_analysis)
                evaluation["repository_url"] = github_url
            
            return evaluation
            
        except Exception as e:
            return {"error": f"Failed to evaluate Go package: {e}"}
    
    def _extract_github_url(self, repository: Any) -> Optional[str]:
        """Extract GitHub URL from repository field"""
        if isinstance(repository, dict):
            url = repository.get("url", "")
        elif isinstance(repository, str):
            url = repository
        else:
            return None
        
        if "github.com" in url:
            # Clean up the URL
            url = url.replace("git+", "").replace("git://", "https://")
            if url.endswith(".git"):
                url = url[:-4]
            return url.rstrip('/')
        
        return None
    
    def _find_github_in_urls(self, urls_dict: Dict) -> Optional[str]:
        """Find GitHub URL in project URLs dictionary"""
        if not isinstance(urls_dict, dict):
            return None
        
        for url in urls_dict.values():
            if isinstance(url, str) and "github.com" in url:
                return url.rstrip('/')
        
        return None
    
    async def _analyze_github_repo(self, repo_url: str) -> Dict[str, Any]:
        """Enhanced GitHub repository analysis"""
        try:
            parsed = urlparse(repo_url)
            path_parts = [p for p in parsed.path.split('/') if p]
            
            if len(path_parts) < 2:
                return {"github_error": "Invalid GitHub URL format"}
            
            owner, repo = path_parts[0], path_parts[1]
            api_url = f"{GITHUB_API_ROOT}/repos/{owner}/{repo}"
            
            # Get basic repo info
            repo_data = self.http_client.make_request(api_url, timeout=GITHUB_REQUEST_TIMEOUT)
            if not repo_data:
                return {"github_error": "Repository data not available"}
            
            # Get additional data
            releases_url = f"{api_url}/releases"
            releases_data = self.http_client.make_request(releases_url)
            
            contributors_url = f"{api_url}/contributors"
            contributors_data = self.http_client.make_request(contributors_url)
            
            # Security analysis
            security_data = await self._analyze_github_security(owner, repo)
            
            license_obj = repo_data.get("license")
            
            analysis = {
                "github_stars": repo_data.get("stargazers_count", 0),
                "github_forks": repo_data.get("forks_count", 0),
                "github_open_issues": repo_data.get("open_issues_count", 0),
                "github_watchers": repo_data.get("watchers_count", 0),
                "last_updated": repo_data.get("updated_at", ""),
                "created_at": repo_data.get("created_at", ""),
                "has_license": license_obj is not None,
                "license_name": license_obj.get("name") if license_obj else "No license",
                "default_branch": repo_data.get("default_branch", "main"),
                "archived": repo_data.get("archived", False),
                "topics": repo_data.get("topics", [])
            }
            
            # Release information
            if releases_data:
                analysis["total_releases"] = len(releases_data)
                if releases_data:
                    latest_release = releases_data[0]
                    analysis["latest_release"] = {
                        "tag_name": latest_release.get("tag_name", ""),
                        "published_at": latest_release.get("published_at", ""),
                        "prerelease": latest_release.get("prerelease", False)
                    }
            
            # Contributor information
            if contributors_data:
                analysis["contributor_count"] = len(contributors_data)
                analysis["top_contributors"] = [
                    {"login": c.get("login", ""), "contributions": c.get("contributions", 0)}
                    for c in contributors_data[:5]
                ]
            
            # Security analysis
            analysis.update(security_data)
            
            return analysis
            
        except Exception as e:
            return {"github_error": f"Analysis failed: {e}"}
    
    async def _analyze_github_security(self, owner: str, repo: str) -> Dict[str, Any]:
        """Analyze GitHub repository security features"""
        security_analysis = {
            "has_security_policy": False,
            "has_vulnerability_alerts": False,
            "dependency_graph_enabled": False,
            "security_advisories": 0
        }
        
        try:
            # Check for security policy
            security_url = f"{GITHUB_API_ROOT}/repos/{owner}/{repo}/community/profile"
            community_data = self.http_client.make_request(security_url)
            if community_data:
                files = community_data.get("files", {})
                security_analysis["has_security_policy"] = bool(files.get("security"))
            
            # Check for security advisories
            advisories_url = f"{GITHUB_API_ROOT}/repos/{owner}/{repo}/security-advisories"
            advisories_data = self.http_client.make_request(advisories_url)
            if advisories_data:
                security_analysis["security_advisories"] = len(advisories_data)
            
        except Exception as e:
            logger.debug(f"Security analysis failed for {owner}/{repo}: {e}")
        
        return security_analysis
    
    def _calculate_comprehensive_score(self, evaluation: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive OpenSSF score"""
        score = 0
        max_score = 100
        
        # Component 1: License (15 points)
        if evaluation.get("has_license"):
            score += 15
        
        # Component 2: Repository presence and quality (20 points)
        if evaluation.get("repository_url") and not evaluation.get("github_error"):
            score += 10  # Has repository
            
            # Additional points for repository quality
            stars = evaluation.get("github_stars", 0)
            if stars >= 100:
                score += 5
            if stars >= 1000:
                score += 5
        
        # Component 3: Vulnerability analysis (30 points)
        vuln_analysis = evaluation.get("vulnerability_analysis", {})
        total_vulns = vuln_analysis.get("total_vulnerabilities", 0)
        
        if total_vulns == 0:
            score += 30
        else:
            severity = vuln_analysis.get("severity_breakdown", {})
            deduction = (
                severity.get("CRITICAL", 0) * 12 +
                severity.get("HIGH", 0) * 8 +
                severity.get("MEDIUM", 0) * 4 +
                severity.get("LOW", 0) * 2
            )
            score += max(0, 30 - deduction)
        
        # Component 4: Supply chain security (20 points)
        supply_chain = evaluation.get("supply_chain_analysis", {})
        if supply_chain:
            overall_risk = supply_chain.get("overall_risk", "CRITICAL")
            if overall_risk == "LOW":
                score += 20
            elif overall_risk == "MEDIUM":
                score += 15
            elif overall_risk == "HIGH":
                score += 10
            else:  # CRITICAL
                score += 5
        else:
            score += 10  # Default if no analysis
        
        # Component 5: Maintenance and activity (15 points)
        if evaluation.get("latest_version") and evaluation.get("latest_version") != "unknown":
            score += 5
        
        if evaluation.get("last_updated"):
            try:
                last_update = datetime.fromisoformat(evaluation["last_updated"].replace("Z", "+00:00"))
                days_since_update = (datetime.now(last_update.tzinfo) - last_update).days
                
                if days_since_update <= 30:
                    score += 10
                elif days_since_update <= 90:
                    score += 7
                elif days_since_update <= 180:
                    score += 5
                elif days_since_update <= 365:
                    score += 3
            except (ValueError, TypeError):
                pass
        
        # Ensure score is within bounds
        final_score = max(0, min(max_score, score))
        percentage = final_score
        
        # Determine risk level
        if percentage >= 85:
            risk_level = "LOW"
        elif percentage >= 70:
            risk_level = "MEDIUM"
        elif percentage >= 50:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        return {
            "score": final_score,
            "percentage": percentage,
            "risk_level": risk_level,
            "max_possible_score": max_score
        }
    
    def _generate_comprehensive_recommendations(self, evaluation: Dict[str, Any]) -> List[str]:
        """Generate comprehensive recommendations"""
        recommendations = []
        score_data = evaluation.get("openssf_score", {})
        risk_level = score_data.get("risk_level", "UNKNOWN")
        
        # Risk level recommendations
        if risk_level == "LOW":
            recommendations.append("✅ This package appears safe to use with good security practices")
        elif risk_level == "MEDIUM":
            recommendations.append("⚠️ Use with standard security practices and regular monitoring")
        elif risk_level == "HIGH":
            recommendations.append("⚠️ Use with significant caution - implement additional security measures")
        else:
            recommendations.append("🚨 HIGH RISK - Strongly recommend finding alternatives or extensive security review")
        
        # Vulnerability-specific recommendations
        vuln_analysis = evaluation.get("vulnerability_analysis", {})
        if vuln_analysis.get("total_vulnerabilities", 0) > 0:
            severity = vuln_analysis.get("severity_breakdown", {})
            if severity.get("CRITICAL", 0) > 0:
                recommendations.append("🚨 CRITICAL vulnerabilities found - immediate patching required")
            if severity.get("HIGH", 0) > 0:
                recommendations.append("⚠️ HIGH severity vulnerabilities found - urgent updates needed")
        
        # Supply chain recommendations
        supply_chain = evaluation.get("supply_chain_analysis", {})
        if supply_chain:
            if supply_chain.get("overall_risk") in ["HIGH", "CRITICAL"]:
                recommendations.append("🔗 Supply chain risks detected - verify package authenticity")
            
            typosquat = supply_chain.get("typosquatting_risk", {})
            if typosquat.get("risk_level") == "HIGH":
                recommendations.append("⚠️ Potential typosquatting risk - verify package name carefully")
        
        # Repository recommendations
        if not evaluation.get("repository_url"):
            recommendations.append("📁 No public repository found - verify package legitimacy")
        elif evaluation.get("github_error"):
            recommendations.append(f"📁 Repository analysis failed: {evaluation['github_error']}")
        
        # License recommendations
        if not evaluation.get("has_license"):
            recommendations.append("⚖️ No license detected - verify legal compliance before use")
        
        # Maintenance recommendations
        if evaluation.get("archived"):
            recommendations.append("📦 Repository is archived - package may not receive updates")
        
        return recommendations
    
    def _needs_alternatives(self, evaluation: Dict[str, Any]) -> bool:
        """Determine if alternatives should be suggested"""
        score_data = evaluation.get("openssf_score", {})
        vuln_analysis = evaluation.get("vulnerability_analysis", {})
        supply_chain = evaluation.get("supply_chain_analysis", {})
        
        # High risk factors that warrant alternatives
        risk_factors = []
        
        if score_data.get("risk_level") in ["HIGH", "CRITICAL"]:
            risk_factors.append("overall_risk")
        
        severity = vuln_analysis.get("severity_breakdown", {})
        if severity.get("CRITICAL", 0) > 0 or severity.get("HIGH", 0) > 0:
            risk_factors.append("vulnerabilities")
        
        if supply_chain and supply_chain.get("overall_risk") in ["HIGH", "CRITICAL"]:
            risk_factors.append("supply_chain")
        
        if evaluation.get("archived"):
            risk_factors.append("archived")
        
        return len(risk_factors) >= 1
    
    def _record_evaluation_metrics(self, evaluation: Dict[str, Any], duration: float):
        """Record evaluation metrics"""
        try:
            score_data = evaluation.get("openssf_score", {})
            vuln_analysis = evaluation.get("vulnerability_analysis", {})
            
            metrics = EvaluationMetrics(
                package_name=evaluation.get("package_name", ""),
                package_manager=evaluation.get("package_manager", ""),
                version=evaluation.get("target_version"),
                duration=duration,
                cache_hits=getattr(self.http_client.cache, 'hits', 0),
                cache_misses=getattr(self.http_client.cache, 'misses', 0),
                api_calls=getattr(self.http_client, 'api_calls', 0),
                vulnerability_count=vuln_analysis.get("total_vulnerabilities", 0),
                score=score_data.get("score", 0),
                risk_level=score_data.get("risk_level", "UNKNOWN"),
                timestamp=datetime.now(UTC)            )
            
            # Record to global metrics collector
            if hasattr(self, 'metrics_collector'):
                self.metrics_collector.record_evaluation(metrics)
                
        except Exception as e:
            logger.debug(f"Failed to record metrics: {e}")

# Initialize global components
config = Config()
cache_manager = CacheManager(
    cache_dir=DEFAULT_CACHE_DIR, 
    cache_duration_hours=config.cache_duration_hours
)

http_client = HTTPClient(cache_manager, config)
metrics_collector = MetricsCollector()

# Initialize main components
evaluator = MultiPackageManagerEvaluator(http_client, config)
alternative_finder = EnhancedAlternativeFinder(http_client, config)

# Attach metrics collector to evaluator
evaluator.metrics_collector = metrics_collector

# Initialize FastMCP server
mcp = FastMCP("Enhanced OpenSSF Security Evaluator v3.0")

# Rich output functions
def print_rich_table(data: List[Dict], title: str):
    """Print data as a rich table"""
    if not RICH_AVAILABLE or not data:
        return
    
    table = Table(title=title)
    
    # Add columns based on first item
    for key in data[0].keys():
        table.add_column(key.replace("_", " ").title())
    
    # Add rows
    for item in data:
        table.add_row(*[str(v) for v in item.values()])
    
    console.print(table)

def print_rich_panel(content: str, title: str, style: str = "blue"):
    """Print content in a rich panel"""
    if not RICH_AVAILABLE:
        print(f"\n{title}:\n{content}")
        return
    
    panel = Panel(content, title=title, border_style=style)
    console.print(panel)

def format_markdown_output(content: str) -> str:
    """Format and display markdown content (MCP-safe)"""
    # In MCP server mode, never print to stdout - just return the content
    # Rich output would interfere with MCP JSON protocol
    return content


# Core implementation functions
async def _run_evaluate_package(package_name: str, package_manager: str = "npm", version: Optional[str] = None) -> str:
    """Core evaluation implementation"""
    if RICH_AVAILABLE:
        with console.status(f"[bold green]Evaluating {package_name} ({package_manager})..."):
            result = await evaluator.evaluate_package(package_name, package_manager, version)
    else:
        result = await evaluator.evaluate_package(package_name, package_manager, version)
    
    if "error" in result:
        return f"❌ Error: {result['error']}"
    
    # Generate comprehensive report
    report_lines = []
    
    # Header
    version_info = f" v{result.get('target_version', 'latest')}" if result.get('target_version') != result.get('latest_version') else ""
    report_lines.extend([
        f"# 🛡️ Enhanced Security Evaluation: `{result.get('package_name')}`{version_info}",
        f"**Package Manager:** {result.get('package_manager', '').upper()}",
        f"**Evaluation Date:** {result.get('evaluation_date', '')}",
        ""
    ])
    
    # Package Information
    report_lines.extend([
        "## 📦 Package Information",
        f"- **Target Version:** {result.get('target_version', 'N/A')}",
        f"- **Latest Version:** {result.get('latest_version', 'N/A')}",
        f"- **Description:** {result.get('description', 'N/A')}",
        f"- **Registry URL:** {result.get('registry_url', 'N/A')}",
        f"- **Repository URL:** {result.get('repository_url', 'Not available')}",
        f"- **License:** {result.get('license_name', result.get('license', 'No license'))}",
        ""
    ])
    
    # Security Score
    score_data = result.get("openssf_score", {})
    report_lines.extend([
        "## 📊 Security Score",
        f"- **Overall Score:** {score_data.get('score', 0):.1f}/{score_data.get('max_possible_score', 100)} ({score_data.get('percentage', 0):.1f}%)",
        f"- **Risk Level:** **{score_data.get('risk_level', 'Unknown')}**",
        ""
    ])
    
    # Vulnerability Analysis
    vuln = result.get("vulnerability_analysis", {})
    report_lines.extend([
        "## 🔍 Vulnerability Analysis",
        f"- **Total Vulnerabilities:** {vuln.get('total_vulnerabilities', 0)}"
    ])
    
    if vuln.get('total_vulnerabilities', 0) > 0:
        severity = vuln.get("severity_breakdown", {})
        report_lines.extend([
            f"  - **Critical:** {severity.get('CRITICAL', 0)}",
            f"  - **High:** {severity.get('HIGH', 0)}",
            f"  - **Medium:** {severity.get('MEDIUM', 0)}",
            f"  - **Low:** {severity.get('LOW', 0)}"
        ])
        
        # Show top vulnerabilities
        vulns = vuln.get("vulnerabilities", [])
        if vulns:
            report_lines.append("\n### Top Vulnerabilities:")
            for i, v in enumerate(vulns[:3], 1):
                report_lines.extend([
                    f"**{i}. {v.get('id', f'Vulnerability {i}')}**",
                    f"   - Severity: {v.get('normalized_severity', 'Unknown')}",
                    f"   - Summary: {v.get('summary', 'No summary')[:100]}{'...' if len(v.get('summary', '')) > 100 else ''}",
                    ""
                ])
    
    report_lines.extend([
        f"- **Recommendation:** {vuln.get('recommendation', 'No recommendation')}",
        ""
    ])
    
    # Supply Chain Analysis
    supply_chain = result.get("supply_chain_analysis")
    if supply_chain:
        report_lines.extend([
            "## 🔗 Supply Chain Security",
            f"- **Overall Risk:** **{supply_chain.get('overall_risk', 'Unknown')}**"
        ])
        
        typosquat = supply_chain.get("typosquatting_risk", {})
        if typosquat.get("risk_level") != "LOW":
            report_lines.append(f"- **Typosquatting Risk:** {typosquat.get('risk_level', 'Unknown')}")
            
            similar = typosquat.get("similar_packages", [])
            if similar:
                report_lines.append("  - Similar packages found:")
                for pkg in similar[:3]:
                    report_lines.append(f"    - `{pkg.get('package', '')}` (similarity: {pkg.get('similarity', 0):.2f})")
        
        patterns = supply_chain.get("suspicious_patterns", {})
        if patterns.get("high_risk_patterns"):
            report_lines.append(f"- **High Risk Patterns:** {len(patterns['high_risk_patterns'])} found")
        
        report_lines.append("")
    
    # Repository Statistics
    github_error = result.get("github_error")
    if github_error:
        report_lines.extend([
            "## 📈 Repository Analysis",
            f"**Error:** {github_error}",
            ""
        ])
    elif result.get("repository_url"):
        report_lines.extend([
            "## 📈 Repository Statistics",
            f"- **⭐ Stars:** {result.get('github_stars', 0):,}",
            f"- **🍴 Forks:** {result.get('github_forks', 0):,}",
            f"- **👥 Contributors:** {result.get('contributor_count', 'N/A')}",
            f"- **🐛 Open Issues:** {result.get('github_open_issues', 0):,}",
            f"- **📅 Last Updated:** {result.get('last_updated', 'N/A')}",
            f"- **🏷️ Total Releases:** {result.get('total_releases', 'N/A')}",
            f"- **📦 Archived:** {'Yes' if result.get('archived') else 'No'}",
            ""
        ])
    
    # SBOM Analysis
    sbom = result.get("sbom_analysis")
    if sbom and "error" not in sbom:
        report_lines.extend([
            "## 📋 Software Bill of Materials (SBOM)",
            f"- **Dependencies Found:** {sbom.get('dependency_count', 0)}",
            ""
        ])
    
    # Recommendations
    recommendations = result.get("recommendations", [])
    if recommendations:
        report_lines.extend([
            "## 💡 Recommendations"
        ])
        for rec in recommendations:
            report_lines.append(f"• {rec}")
        report_lines.append("")
    
    # Alternative Suggestions
    if result.get("needs_alternatives", False):
        report_lines.extend([
            "## 🔄 Alternative Package Suggestions",
            "⚠️ **Based on the security analysis, consider these alternatives:**",
            ""
        ])
        
        alternatives = await alternative_finder.find_alternatives(package_name, package_manager, 3)
        if alternatives:
            for i, alt in enumerate(alternatives, 1):
                report_lines.extend([
                    f"### {i}. `{alt.get('name', 'Unknown')}`",
                    f"- **Description:** {alt.get('description', 'N/A')}",
                    f"- **Score:** {alt.get('final_score', alt.get('score', 0)):.1f}/100",
                    f"- **Registry:** {alt.get('registry_url', 'N/A')}",
                    ""
                ])
        else:
            report_lines.append("No suitable alternatives found automatically. Consider manual research.")
    
    # Footer
    report_lines.extend([
        "---",
        "*Powered by Enhanced OpenSSF Security Evaluator v3.0*",
        "*Includes: OSV vulnerability database, GitHub security analysis, SBOM generation, and supply chain attack detection*"
    ])
    
    content = "\n".join(report_lines)
    return format_markdown_output(content) or content

async def _run_find_alternatives(package_name: str, package_manager: str, max_alternatives: int = 5) -> str:
    """Core alternative finding implementation"""
    if RICH_AVAILABLE:
        with console.status(f"[bold blue]Finding alternatives for {package_name}..."):
            alternatives = await alternative_finder.find_alternatives(package_name, package_manager, max_alternatives)
    else:
        alternatives = await alternative_finder.find_alternatives(package_name, package_manager, max_alternatives)
    
    if not alternatives:
        return f"# 🔍 No Alternatives Found\n\nCould not find suitable alternatives for `{package_name}` ({package_manager.upper()})."
    
    lines = [
        f"# 🔄 Enhanced Alternative Analysis: `{package_name}`",
        f"**Package Manager:** {package_manager.upper()}",
        f"**Found:** {len(alternatives)} alternatives",
        ""
    ]
    
    for i, alt in enumerate(alternatives, 1):
        lines.extend([
            f"## {i}. `{alt.get('name', 'Unknown')}`",
            f"- **Description:** {alt.get('description', 'No description')}",
            f"- **Latest Version:** {alt.get('version', 'unknown')}",
            f"- **Final Score:** {alt.get('final_score', alt.get('score', 0)):.1f}/100",
            f"  - Compatibility: {alt.get('compatibility_score', 0):.1f}/100",
            f"  - Security: {alt.get('security_score', 0):.1f}/100",
            f"  - Maintenance: {alt.get('maintenance_score', 0):.1f}/100",
            f"  - Popularity: {alt.get('popularity_score', 0):.1f}/100",
            f"- **Registry URL:** {alt.get('registry_url', 'N/A')}"
        ])
        
        if alt.get('downloads'):
            lines.append(f"- **Downloads:** {alt.get('downloads'):,}")
        if alt.get('downloads_weekly'):
            lines.append(f"- **Weekly Downloads:** {alt.get('downloads_weekly'):,}")
        
        lines.append("")
    
    lines.extend([
        "## 🎯 Next Steps",
        "1. Use `evaluate_package` tool for detailed security analysis of each alternative",
        "2. Review documentation and API compatibility",
        "3. Test alternatives in a development environment",
        "4. Consider migration effort and breaking changes"
    ])
    
    content = "\n".join(lines)
    return format_markdown_output(content) or content

def _run_scan_vulnerabilities(package_name: str, package_manager: str, version: Optional[str] = None) -> str:
    """Core vulnerability scanning implementation"""
    if RICH_AVAILABLE:
        with console.status(f"[bold red]Scanning vulnerabilities for {package_name}..."):
            results = evaluator.vuln_scanner.scan_package(package_name, package_manager, version)
    else:
        results = evaluator.vuln_scanner.scan_package(package_name, package_manager, version)
    
    total = results.get("total_vulnerabilities", 0)
    
    if total == 0:
        return f"✅ No vulnerabilities found for `{package_name}` ({package_manager}) {f'v{version}' if version else 'latest version'}"
    
    lines = [
        f"# 🔍 Detailed Vulnerability Report: `{package_name}`",
        f"**Package Manager:** {package_manager.upper()}",
        f"**Version:** {version or 'latest'}",
        f"**Scan Date:** {datetime.utcnow().isoformat()}",
        ""
    ]
    
    # Summary
    severity = results.get("severity_breakdown", {})
    lines.extend([
        "## 📊 Summary",
        f"- **Total Vulnerabilities:** {total}",
        f"- **Critical:** {severity.get('CRITICAL', 0)}",
        f"- **High:** {severity.get('HIGH', 0)}",
        f"- **Medium:** {severity.get('MEDIUM', 0)}",
        f"- **Low:** {severity.get('LOW', 0)}",
        f"- **Risk Assessment:** {results.get('recommendation', 'No assessment')}",
        ""
    ])
    
    # Detailed vulnerabilities
    vulnerabilities = results.get("vulnerabilities", [])
    if vulnerabilities:
        lines.append("## 🚨 Vulnerability Details")
        for i, vuln in enumerate(vulnerabilities, 1):
            lines.extend([
                f"### {i}. `{vuln.get('id', f'Vulnerability {i}')}`",
                f"- **Severity:** {vuln.get('normalized_severity', 'Unknown')}",
                f"- **Summary:** {vuln.get('summary', 'No summary available')}",
                f"- **Published:** {vuln.get('published', 'Unknown')}",
                f"- **Modified:** {vuln.get('modified', 'Unknown')}"
            ])
            
            references = vuln.get("references", [])
            if references:
                lines.append("- **References:**")
                for ref in references[:3]:
                    if isinstance(ref, dict):
                        url = ref.get("url", "")
                        if url:
                            lines.append(f"  - {url}")
                    elif isinstance(ref, str):
                        lines.append(f"  - {ref}")
            
            lines.append("")
    
    # Alternative suggestions for high-risk vulnerabilities
    if severity.get("CRITICAL", 0) > 0 or severity.get("HIGH", 0) > 0:
        lines.extend([
            "## 🔄 Recommended Actions",
            "Due to **CRITICAL** or **HIGH** severity vulnerabilities:",
            "",
            "1. **Immediate:** Update to a patched version if available",
            "2. **Short-term:** Consider switching to a secure alternative",
            "3. **Long-term:** Implement automated vulnerability monitoring",
            "",
            "Use the `find_alternatives` tool to discover secure alternatives."
        ])
    
    content = "\n".join(lines)
    return format_markdown_output(content) or content

def _run_get_cache_stats() -> str:
    """Get cache and system statistics"""
    cache_stats = cache_manager.get_stats()
    metrics_summary = metrics_collector.get_summary()
    
    lines = [
        "# 💾 System Statistics",
        "",
        "## Cache Performance",
        f"- **Directory:** `{cache_stats.get('directory', 'N/A')}`",
        f"- **Files:** {cache_stats.get('files', 0):,}",
        f"- **Total Size:** {cache_stats.get('total_size_mb', 0):.2f} MB",
        f"- **Hit Rate:** {cache_stats.get('hit_rate', 0):.1f}%",
        f"- **Hits:** {cache_stats.get('hits', 0):,}",
        f"- **Misses:** {cache_stats.get('misses', 0):,}",
        "",
        "## Evaluation Metrics",
        f"- **Uptime:** {metrics_summary.get('uptime_hours', 0):.1f} hours",
        f"- **Total Evaluations:** {metrics_summary.get('total_evaluations', 0):,}",
        f"- **Evaluations/Hour:** {metrics_summary.get('evaluations_per_hour', 0):.1f}",
        f"- **Average Duration:** {metrics_summary.get('average_duration_seconds', 0):.2f}s",
        f"- **Average Score:** {metrics_summary.get('average_score', 0):.1f}/100",
        f"- **API Calls:** {metrics_summary.get('total_api_calls', 0):,}",
        ""
    ]
    
    # Risk level distribution
    risk_dist = metrics_summary.get('risk_level_distribution', {})
    if risk_dist:
        lines.extend([
            "## Risk Level Distribution",
            f"- **Low:** {risk_dist.get('LOW', 0)}",
            f"- **Medium:** {risk_dist.get('MEDIUM', 0)}",
            f"- **High:** {risk_dist.get('HIGH', 0)}",
            f"- **Critical:** {risk_dist.get('CRITICAL', 0)}",
            ""
        ])
    
    lines.extend([
        "## Configuration",
        f"- **GitHub Token:** {'✅ Configured' if config.github_token else '❌ Not configured'}",
        f"- **SBOM Analysis:** {'✅ Enabled' if config.enable_sbom else '❌ Disabled'}",
        f"- **Supply Chain Checks:** {'✅ Enabled' if config.enable_supply_chain_checks else '❌ Disabled'}",
        f"- **Max Concurrent Requests:** {config.max_concurrent_requests}",
        f"- **Cache Duration:** {config.cache_duration_hours} hours"
    ])
    
    content = "\n".join(lines)
    return format_markdown_output(content) or content

# FastMCP Tool Definitions
@mcp.tool()
def evaluate_package(package_name: str, package_manager: str = "npm", version: Optional[str] = None) -> str:
    """
    Performs comprehensive security evaluation of a software package including vulnerability scanning,
    supply chain analysis, SBOM generation, and GitHub repository analysis.
    
    Args:
        package_name: Name of the package to evaluate
        package_manager: Package manager (npm, pypi, cargo, maven, nuget, rubygems, go)
        version: Specific version to evaluate (optional, defaults to latest)
    
    Returns:
        Detailed security evaluation report with scores, vulnerabilities, and recommendations
    """
    return asyncio.run(_run_evaluate_package(package_name, package_manager, version))

@mcp.tool()
def find_alternatives(package_name: str, package_manager: str, max_alternatives: int = 5) -> str:
    """
    Finds and ranks alternative packages with enhanced compatibility and security scoring.
    
    Args:
        package_name: Name of the package to find alternatives for
        package_manager: Package manager ecosystem
        max_alternatives: Maximum number of alternatives to return
    
    Returns:
        Ranked list of alternative packages with detailed scoring breakdown
    """
    return asyncio.run(_run_find_alternatives(package_name, package_manager, max_alternatives))

@mcp.tool()
def scan_vulnerabilities(package_name: str, package_manager: str, version: Optional[str] = None) -> str:
    """
    Performs detailed vulnerability scanning using OSV database with EPSS scoring.
    
    Args:
        package_name: Name of the package to scan
        package_manager: Package manager ecosystem
        version: Specific version to scan (optional)
    
    Returns:
        Detailed vulnerability report with remediation recommendations
    """
    return _run_scan_vulnerabilities(package_name, package_manager, version)

@mcp.tool()
def analyze_supply_chain(package_name: str, package_manager: str) -> str:
    """
    Analyzes package for supply chain attacks including typosquatting and suspicious patterns.
    
    Args:
        package_name: Name of the package to analyze
        package_manager: Package manager ecosystem
    
    Returns:
        Supply chain security analysis report
    """
    analyzer = SupplyChainAnalyzer(http_client)
    results = analyzer.analyze_package(package_name, package_manager)
    
    lines = [
        f"# 🔗 Supply Chain Security Analysis: `{package_name}`",
        f"**Package Manager:** {package_manager.upper()}",
        f"**Overall Risk:** **{results.get('overall_risk', 'Unknown')}**",
        ""
    ]
    
    # Typosquatting analysis
    typosquat = results.get("typosquatting_risk", {})
    lines.extend([
        "## 🎭 Typosquatting Analysis",
        f"- **Risk Level:** {typosquat.get('risk_level', 'Unknown')}"
    ])
    
    similar_packages = typosquat.get("similar_packages", [])
    if similar_packages:
        lines.append("- **Similar Packages Found:**")
        for pkg in similar_packages:
            lines.append(f"  - `{pkg.get('package', '')}` (similarity: {pkg.get('similarity', 0):.2f})")
    
    risk_patterns = typosquat.get("risk_patterns", [])
    if risk_patterns:
        lines.append("- **Risk Patterns:**")
        for pattern in risk_patterns:
            lines.append(f"  - {pattern}")
    
    lines.append("")
    
    # Suspicious patterns
    patterns = results.get("suspicious_patterns", {})
    lines.extend([
        "## 🚩 Suspicious Patterns",
        f"- **High Risk Patterns:** {len(patterns.get('high_risk_patterns', []))}",
        f"- **Suspicious Patterns:** {len(patterns.get('suspicious_patterns', []))}"
    ])
    
    for pattern in patterns.get("high_risk_patterns", []):
        lines.append(f"  - ⚠️ {pattern}")
    
    for pattern in patterns.get("suspicious_patterns", []):
        lines.append(f"  - ℹ️ {pattern}")
    
    content = "\n".join(lines)
    return format_markdown_output(content) or content

@mcp.tool()
def get_system_stats() -> str:
    """
    Retrieves comprehensive system statistics including cache performance and evaluation metrics.
    
    Returns:
        System statistics and performance metrics
    """
    return _run_get_cache_stats()

@mcp.tool()
def clear_cache() -> str:
    """
    Clears expired cache entries and returns cleanup statistics.
    
    Returns:
        Cache cleanup results
    """
    try:
        before_stats = cache_manager.get_stats()
        cache_manager.clear_expired()
        after_stats = cache_manager.get_stats()
        
        cleared_files = before_stats.get('files', 0) - after_stats.get('files', 0)
        freed_mb = before_stats.get('total_size_mb', 0) - after_stats.get('total_size_mb', 0)
        
        return f"""# 🧹 Cache Cleanup Complete

## Results
- **Files Cleared:** {cleared_files:,}
- **Space Freed:** {freed_mb:.2f} MB
- **Remaining Files:** {after_stats.get('files', 0):,}
- **Current Size:** {after_stats.get('total_size_mb', 0):.2f} MB

Cache cleanup removes expired entries to free up disk space and maintain performance."""
        
    except Exception as e:
        return f"❌ Cache cleanup failed: {e}"

# Enhanced CLI with Rich formatting
def cli_help():
    """Display enhanced help information"""
    help_text = f"""
🛡️ Enhanced OpenSSF Security Evaluator v3.0

Usage:
  python evaluator.py <command> [arguments]

Commands:
  evaluate <package> [manager] [version]     - Evaluate package security
  alternatives <package> <manager> [max]    - Find package alternatives  
  vulnerabilities <package> <manager> [ver] - Scan for vulnerabilities
  supply-chain <package> <manager>          - Analyze supply chain risks
  stats                                     - Show system statistics
  clear-cache                               - Clear expired cache entries
  supported                                 - List supported package managers

Examples:
  python evaluator.py evaluate lodash npm
  python evaluator.py evaluate requests pypi 2.28.0
  python evaluator.py alternatives moment npm 5
  python evaluator.py vulnerabilities minimist npm 1.2.0
  python evaluator.py supply-chain react npm
  python evaluator.py stats

Package Managers Supported:
  npm, pypi, cargo, maven, nuget, rubygems, go
    """
    
    if RICH_AVAILABLE:
        console.print(Panel(help_text, title="OpenSSF Security Evaluator", border_style="blue"))
    else:
        print(help_text)

def main():
    """Command-line interface for the OpenSSF Evaluator"""
    import sys
    
    if len(sys.argv) < 2:
        cli_help()
        return

    command = sys.argv[1].lower()
    
    try:
        if command == "evaluate":
            if len(sys.argv) < 3:
                print("❌ Error: Package name required")
                return
            
            package_name = sys.argv[2]
            package_manager = sys.argv[3] if len(sys.argv) > 3 else "npm"
            version = sys.argv[4] if len(sys.argv) > 4 else None
            
            print(f"🔍 Evaluating {package_name} ({package_manager}) {f'v{version}' if version else 'latest version'}...")
            result = asyncio.run(_run_evaluate_package(package_name, package_manager, version))
            print(result)
            
        elif command == "alternatives":
            if len(sys.argv) < 4:
                print("❌ Error: Package name and manager required")
                return
                
            package_name = sys.argv[2]
            package_manager = sys.argv[3]
            max_alternatives = int(sys.argv[4]) if len(sys.argv) > 4 else 5
            
            print(f"🔄 Finding alternatives for {package_name} ({package_manager})...")
            result = asyncio.run(_run_find_alternatives(package_name, package_manager, max_alternatives))
            print(result)
            
        elif command in ["vulnerabilities", "vulns", "scan"]:
            if len(sys.argv) < 4:
                print("❌ Error: Package name and manager required")
                return
                
            package_name = sys.argv[2]
            package_manager = sys.argv[3]
            version = sys.argv[4] if len(sys.argv) > 4 else None
            
            print(f"🔍 Scanning vulnerabilities for {package_name} ({package_manager}) {f'v{version}' if version else 'all versions'}...")
            result = _run_scan_vulnerabilities(package_name, package_manager, version)
            print(result)
            
        elif command in ["supply-chain", "supply_chain", "sc"]:
            if len(sys.argv) < 4:
                print("❌ Error: Package name and manager required")
                return
                
            package_name = sys.argv[2]
            package_manager = sys.argv[3]
            
            print(f"🔗 Analyzing supply chain for {package_name} ({package_manager})...")
            # Call the implementation function directly
            analyzer = SupplyChainAnalyzer(http_client)
            results = analyzer.analyze_package(package_name, package_manager)
            
            lines = [
                f"# 🔗 Supply Chain Security Analysis: `{package_name}`",
                f"**Package Manager:** {package_manager.upper()}",
                f"**Overall Risk:** **{results.get('overall_risk', 'Unknown')}**",
                ""
            ]
            
            # Typosquatting analysis
            typosquat = results.get("typosquatting_risk", {})
            lines.extend([
                "## 🎭 Typosquatting Analysis",
                f"- **Risk Level:** {typosquat.get('risk_level', 'Unknown')}"
            ])
            
            similar_packages = typosquat.get("similar_packages", [])
            if similar_packages:
                lines.append("- **Similar Packages Found:**")
                for pkg in similar_packages:
                    lines.append(f"  - `{pkg.get('package', '')}` (similarity: {pkg.get('similarity', 0):.2f})")
            
            risk_patterns = typosquat.get("risk_patterns", [])
            if risk_patterns:
                lines.append("- **Risk Patterns:**")
                for pattern in risk_patterns:
                    lines.append(f"  - {pattern}")
            
            lines.append("")
            
            # Suspicious patterns
            patterns = results.get("suspicious_patterns", {})
            lines.extend([
                "## 🚩 Suspicious Patterns",
                f"- **High Risk Patterns:** {len(patterns.get('high_risk_patterns', []))}",
                f"- **Suspicious Patterns:** {len(patterns.get('suspicious_patterns', []))}"
            ])
            
            for pattern in patterns.get("high_risk_patterns", []):
                lines.append(f"  - ⚠️ {pattern}")
            
            for pattern in patterns.get("suspicious_patterns", []):
                lines.append(f"  - ℹ️ {pattern}")
            
            result = "\n".join(lines)
            print(format_markdown_output(result) or result)
            
        elif command in ["stats", "statistics"]:
            print("📊 Gathering system statistics...")
            result = _run_get_cache_stats()
            print(result)
            
        elif command in ["clear-cache", "clear_cache", "clearcache"]:
            print("🧹 Clearing cache...")
            try:
                before_stats = cache_manager.get_stats()
                cache_manager.clear_expired()
                after_stats = cache_manager.get_stats()
                
                cleared_files = before_stats.get('files', 0) - after_stats.get('files', 0)
                freed_mb = before_stats.get('total_size_mb', 0) - after_stats.get('total_size_mb', 0)
                
                result = f"""# 🧹 Cache Cleanup Complete

## Results
- **Files Cleared:** {cleared_files:,}
- **Space Freed:** {freed_mb:.2f} MB
- **Remaining Files:** {after_stats.get('files', 0):,}
- **Current Size:** {after_stats.get('total_size_mb', 0):.2f} MB

Cache cleanup removes expired entries to free up disk space and maintain performance."""
                print(result)
                
            except Exception as e:
                print(f"❌ Cache cleanup failed: {e}")
            
        elif command in ["supported", "support", "managers"]:
            supported_text = """
# 📦 Supported Package Managers

**OpenSSF Evaluator v3.0** supports the following package ecosystems:

- **npm** (Node.js) - Full support with downloads
- **PyPI** (Python) - Full support  
- **Cargo** (Rust) - Full support with downloads
- **Maven** (Java) - Full support with POM analysis
- **NuGet** (.NET) - Full support with metadata
- **RubyGems** (Ruby) - Full support
- **Go Modules** (Go) - Basic support

Examples:
  python evaluator.py evaluate lodash npm
  python evaluator.py evaluate requests pypi
  python evaluator.py evaluate serde cargo
  python evaluator.py evaluate junit:junit maven
            """
            print(supported_text)
            
        else:
            print(f"❌ Error: Unknown command '{command}'")
            print("Use 'python evaluator.py' without arguments to see usage.")
            
    except KeyboardInterrupt:
        print("\n\n⚠️ Operation cancelled by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        logger.exception("CLI command failed")

def run_mcp_server():
    """Run the MCP server (synchronous)"""
    try:
        import sys
        import os
        
        # Create logs directory if it doesn't exist
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        
        # CRITICAL: For MCP, stdout must ONLY contain JSON messages
        # All logging must go to stderr or files, never stdout
        
        # Clear any existing handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        
        # Set up logging for MCP mode - NO STDOUT LOGGING
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            handlers=[
                logging.StreamHandler(sys.stderr),  # Use stderr only
                logging.FileHandler("logs/mcp_server.log", encoding='utf-8')
            ],
            force=True
        )
        
        # Log to stderr so it doesn't interfere with MCP JSON protocol
        logger.info("Starting Enhanced OpenSSF Security Evaluator MCP Server v3.0")
        logger.info(f"Process ID: {os.getpid()}")
        logger.info("Ready to serve security evaluation requests")
        
        # Run the FastMCP server - this will handle stdout JSON communication
        mcp.run()
        
    except Exception as e:
        # Log errors to stderr, not stdout
        logger.exception(f"MCP Server failed to start: {e}")
        raise


if __name__ == "__main__":
    import sys
    
    # Detect if running as MCP server (no arguments means MCP mode)
    if len(sys.argv) == 1:
        # MCP SERVER MODE: stdout reserved for JSON protocol only
        # All other output must go to stderr or log files
        try:
            run_mcp_server()
        except KeyboardInterrupt:
            # Log to stderr, not stdout
            print("MCP Server stopped by user", file=sys.stderr)
        except Exception as e:
            # Log to stderr, not stdout  
            print(f"MCP Server error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # CLI MODE: normal output to stdout is fine
        main()

