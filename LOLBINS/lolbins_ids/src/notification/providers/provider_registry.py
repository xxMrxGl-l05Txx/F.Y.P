# src/notification/providers/provider_registry.py
import logging
from .tkinter_notifier import TkinterNotifierProvider
from .websocket_provider import WebSocketProvider

# Import the email provider if needed
try:
    from .email_provider import EmailProvider
    EMAIL_AVAILABLE = True
except ImportError:
    EMAIL_AVAILABLE = False
    logging.warning("Email provider dependencies not available")

class ProviderRegistry:
    @staticmethod
    def get_provider(provider_name, config):
        """Get provider instance by name"""
        providers = {
            'system_tray': TkinterNotifierProvider,
            'email': EmailProvider if EMAIL_AVAILABLE else None,
            'websocket': WebSocketProvider  # Properly reference the WebSocketProvider
        }
        
        if provider_name in providers and providers[provider_name]:
            try:
                provider = providers[provider_name](config)
                logging.info(f"Successfully initialized {provider_name} provider")
                return provider
            except Exception as e:
                logging.error(f"Error initializing {provider_name} provider: {str(e)}")
        
        return None