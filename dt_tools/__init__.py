# Package style __init__.py to handle namespace

__path__ = __import__('pkgutil').extend_path(__path__, __name__)
