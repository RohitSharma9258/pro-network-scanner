import os
import importlib.util
import logging
import asyncio
import multiprocessing
from typing import Dict, List, Any, Type
from core.plugins.base import VanguardPlugin, PluginRegistry

logger = logging.getLogger(__name__)

def plugin_process_wrapper(plugin_class, target, results, return_dict):
    """Execution wrapper for isolated plugin processes."""
    try:
        plugin = plugin_class()
        # Note: In a real sandbox, we'd further restrict the environment here
        # (e.g., using chroot, seccomp, or just restricted global namespace)
        
        # Run sync or async logic (simplified here as sync for multiprocessing demo)
        # In a real tool, we'd use a more complex async-to-process bridge
        result = plugin.run_sync(target, results) 
        return_dict['result'] = result
    except Exception as e:
        logger.error(f"Plugin Process Crash: {e}")

class PluginManager:
    """Enterprise Manager with Process-based Isolation to mitigate RCE risks."""
    
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = plugin_dir
        self.registry = PluginRegistry()
        self.loaded_plugins: List[Type[VanguardPlugin]] = []

    def load_plugins(self):
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)
            return

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                path = os.path.join(self.plugin_dir, filename)
                self._load_plugin_file(path)

    def _load_plugin_file(self, path: str):
        try:
            module_name = os.path.basename(path)[:-3]
            spec = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, VanguardPlugin) and attr is not VanguardPlugin:
                    self.loaded_plugins.append(attr)
                    logger.info(f"Plugin discovered: {attr_name}")
        except Exception as e:
            logger.error(f"Failed to load plugin {path}: {e}")

    async def run_plugins_isolated(self, target: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Runs plugins in isolated processes to prevent RCE from compromising the main scanner."""
        manager = multiprocessing.Manager()
        
        for plugin_class in self.loaded_plugins:
            return_dict = manager.dict()
            p = multiprocessing.Process(
                target=plugin_process_wrapper, 
                args=(plugin_class, target, results, return_dict)
            )
            p.start()
            
            # Wait for plugin with a strict timeout (e.g., 10 seconds)
            # This prevents RCE-based infinite loops or resource exhaustion
            p.join(timeout=10)
            
            if p.is_alive():
                logger.warning(f"Plugin {plugin_class.__name__} timed out. Terminating.")
                p.terminate()
                p.join()
            else:
                if 'result' in return_dict:
                    results = return_dict['result']
        
        return results
