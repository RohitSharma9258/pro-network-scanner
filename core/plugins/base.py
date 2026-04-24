import abc
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class VanguardPlugin(abc.ABC):
    """Base class for all Vanguard plugins with safety wrappers."""
    
    @property
    @abc.abstractmethod
    def name(self) -> str: pass

    @abc.abstractmethod
    async def run(self, target: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute plugin logic. Must return modified results or info."""
        pass

    async def safe_run(self, target: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Safe wrapper to prevent plugin crashes from breaking the scanner."""
        try:
            return await self.run(target, results)
        except Exception as e:
            logger.error(f"Plugin {self.name} failed on {target}: {e}")
            return results

    def run_sync(self, target: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronous wrapper for running in isolated processes."""
        import asyncio
        try:
            return asyncio.run(self.run(target, results))
        except Exception as e:
            logger.error(f"Plugin Sync Wrapper Error: {e}")
            return results

class PluginRegistry:
    """Registry to manage plugin loading and execution."""
    def __init__(self):
        self.plugins = []

    def register(self, plugin: VanguardPlugin):
        self.plugins.append(plugin)
        logger.info(f"Registered plugin: {plugin.name}")

    async def run_all(self, target: str, results: Dict[str, Any]) -> Dict[str, Any]:
        for plugin in self.plugins:
            results = await plugin.safe_run(target, results)
        return results
